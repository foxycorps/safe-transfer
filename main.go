package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"compress/gzip"
)

const BUFFER_SIZE = 4096

var (
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	serverCert tls.Certificate
	caCertPool *x509.CertPool
	startPort  = 49152            // Dynamic port range starting port
	endPort    = 65535            // Dynamic port range ending port
	secretKey  = make([]byte, 32) // AES-256 key
)

func init() {
	_, err := rand.Read(secretKey)
	if err != nil {
		panic(err)
	}
	// Generate an RSA key pair
	privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	publicKey = &privateKey.PublicKey
	generateSelfSignedCert()
}

// Helper function to generate a self-signed certificate for TLS
func generateSelfSignedCert() {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
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

	certBytes, _ := x509.CreateCertificate(rand.Reader, cert, cert, &priv.PublicKey, priv)
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
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
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

func getDynamicPort() string {
	port := rand.Intn(endPort-startPort) + startPort
	return fmt.Sprintf("%d", port)
}

// Send a file with encryption, compression, and authentication
func sendFile(conn net.Conn, path string, baseDir string) {
	defer conn.Close()

	relPath, err := filepath.Rel(baseDir, path)
	if err != nil {
		fmt.Println("Error determining relative path:", err)
		return
	}

	conn.Write([]byte(relPath + "\n"))

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

		conn.Write(append(encryptedData, hmacSignature...))

		// Add random delay to avoid detection via traffic analysis
		time.Sleep(time.Millisecond * time.Duration(rand.Intn(100)))
	}
	fmt.Println("File sent successfully:", relPath)
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
		data := buf[:n-len(sha256.New().Size())]
		expectedHMAC := buf[n-len(sha256.New().Size()):]

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
		time.Sleep(time.Millisecond * time.Duration(rand.Intn(100)))
	}
	fmt.Println("File received successfully:", fullPath)
}

// Orchestrator function to manage connections between sender and receiver
func orchestrator() {
	port := getDynamicPort()
	ln, err := tls.Listen("tcp", ":"+port, &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    caCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	})
	if err != nil {
		panic("Error starting listener: " + err.Error())
	}
	defer ln.Close()

	fmt.Println("Orchestrator is running on port", port)

	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Println("Error accepting connection:", err)
			continue
		}
		go func() {
			filename := receiveFileListener(conn)
			if filename != "" {
				rcvConn, err := net.Dial("tcp", "localhost:"+FILE_INFO_PORT)
				if err != nil {
					fmt.Println("Error connecting to receiver:", err)
					return
				}
				sendFile(rcvConn, filename, ".")
			}
		}()
	}
}

// Sender function to send files or directories to the orchestrator
func sender(sourcePath string, orchestratorIP string) {
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
func receiver(baseDir string) {
	port := getDynamicPort()
	ln, err := tls.Listen("tcp", ":"+port, &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    caCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	})
	if err != nil {
		panic("Error starting listener: " + err.Error())
	}
	defer ln.Close()

	fmt.Println("Receiver is running on port", port)

	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Println("Error accepting connection:", err)
			continue
		}
		go receiveFile(conn, baseDir)
	}
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
		data := buf[:n-len(sha256.New().Size())]
		expectedHMAC := buf[n-len(sha256.New().Size()):]

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
		if *destDir == "" {
			fmt.Println("Usage: -mode=receive -destDir=<destination_directory>")
			return
		}
		receiver(*destDir)
	default:
		fmt.Println("Invalid mode. Use one of: orchestrator, send, receive")
	}
}
