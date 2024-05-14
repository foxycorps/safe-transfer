package main

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"io"
	"math/big"
	mathrand "math/rand"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	BUFFER_SIZE       = 4096
	HASH_SIZE         = 32      // SHA-256 size
	ORCHESTRATOR_PORT = "54321" // Fixed port for the orchestrator
)

var (
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	serverCert tls.Certificate
	caCertPool *x509.CertPool
	secretKey  = make([]byte, 32) // AES-256 key
)

func init() {
	_, err := cryptorand.Read(secretKey)
	if err != nil {
		panic(err)
	}
	// Generate an RSA key pair
	privateKey, err = rsa.GenerateKey(cryptorand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	publicKey = &privateKey.PublicKey
	generateSelfSignedCert()
}

// Helper function to generate a self-signed certificate for TLS
func generateSelfSignedCert() {
	priv, _ := rsa.GenerateKey(cryptorand.Reader, 2048)
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"HiddenFileTransfer"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(1, 0, 0), // Valid for one year
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certBytes, _ := x509.CreateCertificate(cryptorand.Reader, cert, cert, &priv.PublicKey, priv)
	serverCert = tls.Certificate{
		Certificate: [][]byte{certBytes},
		PrivateKey:  priv,
	}

	caCertPool = x509.NewCertPool()
	caCertPool.AddCert(cert)
}

// Encrypt a message using AES encryption
func encrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(secretKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(cryptorand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, data, nil), nil
}

// Decrypt a message using AES decryption
func decrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(secretKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// Compress data
func compress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(data); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Decompress data
func decompress(data []byte) ([]byte, error) {
	buf := bytes.NewBuffer(data)
	gz, err := gzip.NewReader(buf)
	if err != nil {
		return nil, err
	}
	defer gz.Close()

	var out bytes.Buffer
	if _, err := io.Copy(&out, gz); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// Resolve `~` to user's home directory
func resolvePath(p string) string {
	if strings.HasPrefix(p, "~/") {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			panic(err)
		}
		return filepath.Join(homeDir, p[2:])
	}
	return p
}

// Send a file with encryption, compression, and authentication
func sendFile(conn net.Conn, path string, baseDir string) {
	defer conn.Close()

	relPath, err := filepath.Rel(baseDir, path)
	if err != nil {
		fmt.Println("Error determining relative path:", err)
		return
	}

	_, err = conn.Write([]byte(relPath + "\n"))
	if err != nil {
		fmt.Println("Error sending file name:", err)
		return
	}

	inFile, err := os.Open(path)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer inFile.Close()

	buf := make([]byte, BUFFER_SIZE)
	for {
		n, err := inFile.Read(buf)
		if err != nil {
			if err == io.EOF {
				break
			}
			fmt.Println("Error reading file:", err)
			return
		}

		// Compress and encrypt before sending
		compressedData, err := compress(buf[:n])
		if err != nil {
			fmt.Println("Error compressing:", err)
			continue
		}

		encryptedData, err := encrypt(compressedData)
		if err != nil {
			fmt.Println("Error encrypting:", err)
			continue
		}

		// Sign the encrypted data with HMAC
		h := hmac.New(sha256.New, secretKey)
		h.Write(encryptedData)
		hmacSignature := h.Sum(nil)

		_, err = conn.Write(append(encryptedData, hmacSignature...))
		if err != nil {
			fmt.Println("Error sending file data:", err)
			continue
		}

		// Add random delay to avoid detection via traffic analysis
		time.Sleep(time.Millisecond * time.Duration(mathrand.Intn(100)))
	}
	fmt.Printf("File sent successfully: %s\n", relPath)
}

// Receive a file with decryption, decompression, and authentication
func receiveFile(conn net.Conn, baseDir string) {
	defer conn.Close()

	buf := make([]byte, BUFFER_SIZE)
	n, err := conn.Read(buf)
	if err != nil {
		fmt.Println("Error receiving directory/file info:", err)
		return
	}

	relPath := strings.TrimSpace(string(buf[:n]))
	fullPath := filepath.Join(baseDir, relPath)
	err = os.MkdirAll(filepath.Dir(fullPath), os.ModePerm)
	if err != nil {
		fmt.Println("Error creating directories:", err)
		return
	}

	outFile, err := os.Create(fullPath)
	if err != nil {
		fmt.Println("Error creating file:", err)
		return
	}
	defer outFile.Close()

	for {
		n, err = conn.Read(buf)
		if err != nil {
			if err == io.EOF {
				break
			}
			fmt.Println("Error receiving file:", err)
			return
		}

		// Separate HMAC signature from data
		data := buf[:n-HASH_SIZE]
		expectedHMAC := buf[n-HASH_SIZE:]

		// Verify HMAC signature
		h := hmac.New(sha256.New, secretKey)
		h.Write(data)
		calculatedHMAC := h.Sum(nil)
		if !hmac.Equal(expectedHMAC, calculatedHMAC) {
			fmt.Println("HMAC verification failed!")
			return
		}

		// Decrypt and decompress after receiving
		decryptedData, err := decrypt(data)
		if err != nil {
			fmt.Println("Error decrypting:", err)
			continue
		}

		decompressedData, err := decompress(decryptedData)
		if err != nil {
			fmt.Println("Error decompressing:", err)
			continue
		}

		outFile.Write(decompressedData)

		// Add random delay to avoid detection via traffic analysis
		time.Sleep(time.Millisecond * time.Duration(mathrand.Intn(100)))
	}
	fmt.Printf("File received successfully: %s\n", fullPath)
}

// Orchestrator function to manage connections between sender and receiver
func orchestrator() {
	ln, err := tls.Listen("tcp", ":"+ORCHESTRATOR_PORT, &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    caCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	})
	if err != nil {
		panic("Error starting listener: " + err.Error())
	}
	defer ln.Close()

	fmt.Println("Orchestrator is running on port", ORCHESTRATOR_PORT)

	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Println("Error accepting connection:", err)
			continue
		}
		fmt.Println("Device connected:", conn.RemoteAddr())
		go func() {
			defer conn.Close()
			filenameBuffer := make([]byte, BUFFER_SIZE)
			n, err := conn.Read(filenameBuffer)
			if err != nil {
				fmt.Println("Error reading filename:", err)
				return
			}
			filename := strings.TrimSpace(string(filenameBuffer[:n]))
			fmt.Printf("Received transfer request for file: %s\n", filename)

			// Wait for the receiver
			rcvConn, err := ln.Accept()
			if err != nil {
				fmt.Println("Error accepting receiver connection:", err)
				return
			}
			fmt.Println("Receiver connected:", rcvConn.RemoteAddr())
			relayData(conn, rcvConn, filename)
		}()
	}
}

// Relay data between sender and receiver
func relayData(sender net.Conn, receiver net.Conn, filename string) {
	defer receiver.Close()
	buf := make([]byte, BUFFER_SIZE)
	for {
		n, err := sender.Read(buf)
		if err != nil {
			if err == io.EOF {
				break
			}
			fmt.Println("Error reading from sender:", err)
			return
		}

		_, err = receiver.Write(buf[:n])
		if err != nil {
			fmt.Println("Error writing to receiver:", err)
			return
		}
	}
	fmt.Printf("File %s relayed successfully.\n", filename)
}

// Sender function to send files or directories to the orchestrator
func sender(sourcePath string, orchestratorIP string) {
	sourcePath = resolvePath(sourcePath)
	fileInfo, err := os.Stat(sourcePath)
	if err != nil {
		panic("Error getting file info: " + err.Error())
	}

	if fileInfo.IsDir() {
		err = filepath.Walk(sourcePath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			if !info.IsDir() {
				conn, err := net.Dial("tcp", orchestratorIP+":"+ORCHESTRATOR_PORT)
				if err != nil {
					fmt.Println("Error connecting to orchestrator:", err)
					return err
				}
				sendFile(conn, path, sourcePath)
			}
			return nil
		})
		if err != nil {
			fmt.Println("Error walking through the directory:", err)
		}
	} else {
		conn, err := net.Dial("tcp", orchestratorIP+":"+ORCHESTRATOR_PORT)
		if err != nil {
			panic("Error connecting to orchestrator: " + err.Error())
		}
		sendFile(conn, sourcePath, filepath.Dir(sourcePath))
	}
}

// Receiver function to accept incoming files
func receiver(orchestratorIP string, baseDir string) {
	baseDir = resolvePath(baseDir)
	conn, err := net.Dial("tcp", orchestratorIP+":"+ORCHESTRATOR_PORT)
	if err != nil {
		panic("Error connecting to orchestrator: " + err.Error())
	}
	receiveFile(conn, baseDir)
}

// Helper function to receive a file with authentication
func receiveFileListener(conn net.Conn) string {
	defer conn.Close()

	buf := make([]byte, BUFFER_SIZE)
	n, err := conn.Read(buf)
	if err != nil {
		fmt.Println("Error receiving directory/file info:", err)
		return ""
	}

	filename := string(buf[:n])
	outFile, err := os.Create(filename)
	if err != nil {
		fmt.Println("Error creating file:", err)
		return ""
	}
	defer outFile.Close()

	for {
		n, err := conn.Read(buf)
		if err != nil {
			if err == io.EOF {
				break
			}
			fmt.Println("Error receiving file:", err)
			return ""
		}

		// Separate HMAC signature from data
		data := buf[:n-HASH_SIZE]
		expectedHMAC := buf[n-HASH_SIZE:]

		// Verify HMAC signature
		h := hmac.New(sha256.New, secretKey)
		h.Write(data)
		calculatedHMAC := h.Sum(nil)
		if !hmac.Equal(expectedHMAC, calculatedHMAC) {
			fmt.Println("HMAC verification failed!")
			return ""
		}

		// Decrypt and decompress after receiving
		decryptedData, err := decrypt(data)
		if err != nil {
			fmt.Println("Error decrypting:", err)
			continue
		}

		decompressedData, err := decompress(decryptedData)
		if err != nil {
			fmt.Println("Error decompressing:", err)
			continue
		}

		outFile.Write(decompressedData)
	}
	fmt.Println("File received successfully:", filename)
	return filename
}

func main() {
	mode := flag.String("mode", "", "Mode to run: orchestrator, send, or receive")
	sourcePath := flag.String("path", "", "Path to the source file or directory")
	destDir := flag.String("destDir", "", "Destination directory to store received files")
	orchestratorIP := flag.String("orchestrator", "", "Orchestrator IP address")
	flag.Parse()

	switch *mode {
	case "orchestrator":
		orchestrator()
	case "send":
		if *sourcePath == "" || *orchestratorIP == "" {
			fmt.Println("Usage: -mode=send -path=<source_file_or_directory> -orchestrator=<orchestrator_ip>")
			return
		}
		sender(*sourcePath, *orchestratorIP)
	case "receive":
		if *destDir == "" || *orchestratorIP == "" {
			fmt.Println("Usage: -mode=receive -destDir=<destination_directory> -orchestrator=<orchestrator_ip>")
			return
		}
		receiver(*orchestratorIP, *destDir)
	default:
		fmt.Println("Invalid mode. Use one of: orchestrator, send, receive")
	}
}
