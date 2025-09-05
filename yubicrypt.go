package main

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/awnumar/memguard"
	"github.com/go-piv/piv-go/v2/piv"
)

// ecSignature represents an ECDSA signature with R and S components
type ecSignature struct{ R, S *big.Int }

// Supported algorithms
const (
	AlgorithmECCP256 = "ECCP256"
	AlgorithmECCP384 = "ECCP384"
	AlgorithmED25519 = "ED25519"
)

var supportedAlgorithms = map[string]bool{
	AlgorithmECCP256: true,
	AlgorithmECCP384: true,
	AlgorithmED25519: true,
}

// Mapping from elliptic curve to algorithm name
var curveToAlgorithm = map[elliptic.Curve]string{
	elliptic.P256(): elliptic.P256().Params().Name,
	elliptic.P384(): elliptic.P384().Params().Name,
}

// Mapping from elliptic curve to hash function
var curveToHash = map[elliptic.Curve]crypto.Hash{
	elliptic.P256(): crypto.SHA256,
	elliptic.P384(): crypto.SHA384,
}

// Ed25519 constants
const (
	Ed25519SignatureSize = 64
	Ed25519PublicKeySize = 32
	Ed25519CombinedSize  = Ed25519SignatureSize + Ed25519PublicKeySize // 96 bytes
)

const (
	minRSABits = 2048 // Minimum accepted RSA key size
)

// Supported RSA key sizes
var supportedRSASizes = map[int]string{
	2048: "RSA2048",
	3072: "RSA3072",
	4096: "RSA4096",
}

// GUI structure
type GUI struct {
	app            fyne.App
	window         fyne.Window
	themeToggle    *widget.Button
	textArea       *widget.Entry
	pinEntry       *widget.Entry
	statusLabel    *widget.Label
	publicKeyPath  string
	currentTheme   string
	encryptionUsed bool // Tracks if encryption was used in this session
}

func main() {
	defer memguard.Purge()

	gui := &GUI{
		app:            app.NewWithID("oc2mx.net.yubicrypt"),
		currentTheme:   "dark",
		encryptionUsed: false,
	}

	gui.window = gui.app.NewWindow("yubicrypt")
	gui.window.Resize(fyne.NewSize(800, 600))

	gui.createUI()
	gui.applyTheme()

	gui.window.SetContent(gui.createMainUI())
	gui.window.ShowAndRun()
}

// createUI initializes all UI components
func (g *GUI) createUI() {
	monospace := &fyne.TextStyle{Monospace: true}

	g.textArea = widget.NewMultiLineEntry()
	g.textArea.Wrapping = fyne.TextWrapOff
	g.textArea.TextStyle = *monospace
	g.textArea.SetPlaceHolder("Enter text to encrypt, sign, or paste encrypted content here...")

	g.pinEntry = widget.NewPasswordEntry()
	g.pinEntry.SetPlaceHolder("Enter PIN (max 8 chars)")
	g.pinEntry.Validator = func(s string) error {
		if len(s) > 8 {
			return fmt.Errorf("PIN must be max 8 characters")
		}
		return nil
	}

	g.statusLabel = widget.NewLabel("Ready")
	g.statusLabel.Wrapping = fyne.TextWrapWord

	// Theme toggle button
	g.themeToggle = widget.NewButtonWithIcon("", theme.ViewRefreshIcon(), g.toggleTheme)
}

// createMainUI builds the main layout
func (g *GUI) createMainUI() fyne.CanvasObject {
	signTextBtn := widget.NewButtonWithIcon("Sign Text", theme.ConfirmIcon(), g.onSignText)
	verifyTextBtn := widget.NewButtonWithIcon("Verify Text", theme.VisibilityIcon(), g.onVerifyText)

	padBtn := widget.NewButtonWithIcon("Pad", theme.ContentAddIcon(), g.onPad)
	unpadBtn := widget.NewButtonWithIcon("Unpad", theme.ContentRemoveIcon(), g.onUnpad)
	encryptBtn := widget.NewButtonWithIcon("Encrypt", theme.MailComposeIcon(), g.onEncrypt)
	decryptBtn := widget.NewButtonWithIcon("Decrypt", theme.MailForwardIcon(), g.onDecrypt)

	buttonContainer := container.NewHBox(
		layout.NewSpacer(),
		signTextBtn,
		verifyTextBtn,
		padBtn,
		unpadBtn,
		encryptBtn,
		decryptBtn,
		layout.NewSpacer(),
	)

	clearBtn := widget.NewButtonWithIcon("Clear", theme.DeleteIcon(), g.onClear)
	pinContainer := container.NewVBox(
		container.NewHBox(
			layout.NewSpacer(),
			widget.NewLabel("PIN:"),
			g.pinEntry,
			clearBtn,
			layout.NewSpacer(),
		),
	)

	mainContainer := container.NewBorder(
		container.NewVBox(
			container.NewHBox(
				layout.NewSpacer(),
				g.themeToggle,
			),
			buttonContainer,
			widget.NewSeparator(),
		),
		container.NewVBox(
			widget.NewSeparator(),
			pinContainer,
			g.statusLabel,
		),
		nil,
		nil,
		container.NewScroll(g.textArea),
	)

	return mainContainer
}

// toggleTheme switches between light and dark theme
func (g *GUI) toggleTheme() {
	if g.currentTheme == "dark" {
		g.app.Settings().SetTheme(theme.LightTheme())
		g.currentTheme = "light"
		g.themeToggle.SetIcon(theme.ViewRefreshIcon())
	} else {
		g.app.Settings().SetTheme(theme.DarkTheme())
		g.currentTheme = "dark"
		g.themeToggle.SetIcon(theme.ViewRefreshIcon())
	}
}

// applyTheme sets the initial theme
func (g *GUI) applyTheme() {
	if g.currentTheme == "dark" {
		g.app.Settings().SetTheme(theme.DarkTheme())
	} else {
		g.app.Settings().SetTheme(theme.LightTheme())
	}
}

// onSignText triggers the signing process for text in the GUI
func (g *GUI) onSignText() {
	if g.pinEntry.Text == "" {
		g.statusLabel.SetText("Error: PIN required for signing")
		return
	}

	input := g.textArea.Text
	if input == "" {
		g.statusLabel.SetText("Error: No text to sign")
		return
	}

	// Check for existing signature to prevent double signing
	s := string(input)
	for algo := range supportedAlgorithms {
		if strings.Contains(s, "-----BEGIN "+algo+" SIGNATURE-----") {
			g.statusLabel.SetText("Error: Message already contains a signature")
			return
		}
	}

	// Sign data in the text area
	result, err := g.signData([]byte(input), g.pinEntry.Text)
	if err != nil {
		g.statusLabel.SetText("Signing failed: " + err.Error())
		return
	}

	g.textArea.SetText(result)
	g.statusLabel.SetText("✓ Message signed successfully (" + formatByteSize(len(input)) + ")")
}

// onVerifyText triggers the verification process for text in the GUI
func (g *GUI) onVerifyText() {
	input := g.textArea.Text
	if input == "" {
		g.statusLabel.SetText("Error: No text to verify")
		return
	}

	err := g.verifyData([]byte(input))
	if err != nil {
		g.statusLabel.SetText("Verification failed: " + err.Error())
		return
	}

	g.statusLabel.SetText("✓ Signature is valid")
}

// onEncrypt triggers encryption using a public key
func (g *GUI) onEncrypt() {
	if g.encryptionUsed {
		g.statusLabel.SetText("Please select a new certificate for encryption.")
		g.publicKeyPath = ""
		g.choosePublicKey()
		return
	}

	if g.publicKeyPath != "" {
		input := g.textArea.Text
		if input == "" {
			g.statusLabel.SetText("Error: No text to encrypt")
			return
		}

		result, err := g.encryptData([]byte(input), g.publicKeyPath)
		if err != nil {
			g.statusLabel.SetText("Encryption failed: " + err.Error())
			return
		}

		g.encryptionUsed = true
		g.textArea.SetText(result)
		g.statusLabel.SetText("✓ Encrypted with: " + filepath.Base(g.publicKeyPath))
		return
	}

	g.choosePublicKey()
}

// choosePublicKey opens a file dialog to select a PEM certificate
func (g *GUI) choosePublicKey() {
	dialog.ShowFileOpen(func(reader fyne.URIReadCloser, err error) {
		if err != nil {
			g.statusLabel.SetText("Error selecting file: " + err.Error())
			return
		}
		if reader == nil {
			return
		}
		defer reader.Close()

		path := reader.URI().Path()
		if filepath.Ext(path) != ".pem" {
			g.statusLabel.SetText("Error: Please select a .pem file")
			return
		}

		g.publicKeyPath = path
		g.encryptionUsed = false
		g.statusLabel.SetText("Selected public key: " + filepath.Base(path) + " - Encrypting...")

		input := g.textArea.Text
		if input == "" {
			g.statusLabel.SetText("Selected: " + filepath.Base(path) + " - No text to encrypt")
			return
		}

		result, err := g.encryptData([]byte(input), g.publicKeyPath)
		if err != nil {
			g.statusLabel.SetText("Encryption failed: %v" + err.Error())
			return
		}

		g.encryptionUsed = true
		g.textArea.SetText(result)
		g.statusLabel.SetText("✓ Encrypted with: " + filepath.Base(path))
	}, g.window)
}

// onDecrypt triggers decryption using the YubiKey
func (g *GUI) onDecrypt() {
	if g.pinEntry.Text == "" {
		g.statusLabel.SetText("Error: PIN required for decryption")
		return
	}

	input := g.textArea.Text
	if input == "" {
		g.statusLabel.SetText("Error: No text to decrypt")
		return
	}

	result, err := g.decryptData([]byte(input), g.pinEntry.Text)
	if err != nil {
		g.statusLabel.SetText("Decryption failed: " + err.Error())
		return
	}

	g.textArea.SetText(string(result))
	g.statusLabel.SetText("✓ Message decrypted successfully")
}

// onClear resets the UI state
func (g *GUI) onClear() {
	g.textArea.SetText("")
	g.publicKeyPath = ""
	g.encryptionUsed = false

	clipboard := g.app.Clipboard()
	if clipboard != nil {
		clipboard.SetContent("")
	}

	g.statusLabel.SetText("Cleared text area, clipboard and reset encryption state")
}

// signData signs the input data using the YubiKey after hashing
func (g *GUI) signData(data []byte, pin string) (string, error) {
	pinGuard := memguard.NewBufferFromBytes([]byte(pin))
	defer pinGuard.Destroy()

	// Normalize line endings to RFC-compliant CRLF before hashing
	normalizedData := normalizeToRFCCompliantCRLF(data)

	// Display status that we're hashing large document
	if len(normalizedData) > 1024*1024 { // > 1MB
		g.statusLabel.SetText("Hashing large document (" + formatByteSize(len(normalizedData)) + ")...")
		g.window.Canvas().Refresh(g.statusLabel)
	}

	sig, algo, err := g.signDataInternal(pinGuard.Bytes(), normalizedData)
	if err != nil {
		return "", fmt.Errorf("signing failed: %v", err)
	}

	return string(normalizedData) + "\r\n-----BEGIN " + algo + " SIGNATURE-----\r\n" +
		formatSignatureRFC(sig) + "-----END " + algo + " SIGNATURE-----\r\n", nil
}

// signDataInternal performs the actual signing operation
// Uses proper PIV-compliant hash formatting for YubiKey
func (g *GUI) signDataInternal(pin, data []byte) (string, string, error) {
	yk, err := openYubiKey(0)
	if err != nil {
		return "", "", err
	}
	defer yk.Close()

	cert, err := yk.Certificate(piv.SlotSignature)
	if err != nil {
		return "", "", fmt.Errorf("failed to get certificate from signature slot: %v", err)
	}

	// Handle Ed25519 signing
	if ed25519PubKey, ok := cert.PublicKey.(ed25519.PublicKey); ok {
		// Ed25519 signs the hash of the data, not the raw data (YubiKey requirement)
		hash := sha256.Sum256(data)
		return g.signEd25519Data(string(pin), hash[:], ed25519PubKey, yk)
	}

	// Handle ECDSA signing
	pubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return "", "", fmt.Errorf("public key is not ECDSA or Ed25519")
	}

	algorithm, exists := curveToAlgorithm[pubKey.Curve]
	if !exists {
		return "", "", fmt.Errorf("unsupported curve: %v", pubKey.Curve)
	}

	hashFunc := curveToHash[pubKey.Curve]

	// Create hash of the data for ECDSA signing
	var digest []byte
	switch hashFunc {
	case crypto.SHA256:
		h := sha256.New()
		h.Write(data)
		digest = h.Sum(nil)
	case crypto.SHA384:
		h := sha512.New384()
		h.Write(data)
		digest = h.Sum(nil)
	default:
		return "", "", fmt.Errorf("unsupported hash algorithm for curve")
	}

	auth := piv.KeyAuth{PIN: string(pin)}
	priv, err := yk.PrivateKey(piv.SlotSignature, cert.PublicKey, auth)
	if err != nil {
		return "", "", fmt.Errorf("failed to get private key: %v", err)
	}

	signer, ok := priv.(crypto.Signer)
	if !ok {
		return "", "", fmt.Errorf("key does not implement crypto.Signer")
	}

	asn1sig, err := signer.Sign(rand.Reader, digest, nil)
	if err != nil {
		return "", "", fmt.Errorf("signing failed: %v", err)
	}

	var sig ecSignature
	if _, err := asn1.Unmarshal(asn1sig, &sig); err != nil {
		return "", "", fmt.Errorf("ASN.1 unmarshal failed: %v", err)
	}

	curveSize := (pubKey.Curve.Params().BitSize + 7) / 8
	pad := func(b []byte) []byte {
		if len(b) > curveSize {
			b = b[len(b)-curveSize:]
		}
		return append(make([]byte, curveSize-len(b)), b...)
	}

	var raw []byte
	raw = append(raw, pad(pubKey.X.Bytes())...)
	raw = append(raw, pad(pubKey.Y.Bytes())...)
	raw = append(raw, pad(sig.R.Bytes())...)
	raw = append(raw, pad(sig.S.Bytes())...)

	return hex.EncodeToString(raw), algorithm, nil
}

// signEd25519Data handles Ed25519 signing
func (g *GUI) signEd25519Data(pin string, hash []byte, pubKey ed25519.PublicKey, yk *piv.YubiKey) (string, string, error) {
	auth := piv.KeyAuth{PIN: pin}
	priv, err := yk.PrivateKey(piv.SlotSignature, pubKey, auth)
	if err != nil {
		return "", "", fmt.Errorf("failed to get private key: %v", err)
	}

	signer, ok := priv.(crypto.Signer)
	if !ok {
		return "", "", fmt.Errorf("key does not implement crypto.Signer")
	}

	signature, err := signer.Sign(rand.Reader, hash, crypto.Hash(0))
	if err != nil {
		return "", "", fmt.Errorf("Ed25519 signing failed: %v", err)
	}

	combined := append(pubKey, signature...)
	return hex.EncodeToString(combined), AlgorithmED25519, nil
}

// verifyData verifies a signed message
func (g *GUI) verifyData(data []byte) error {
	// First normalize the entire input to RFC-compliant CRLF
	normalizedInput := normalizeToRFCCompliantCRLF(data)
	s := string(normalizedInput)

	var algorithm string
	var beg, end string

	// Find the signature block and determine algorithm
	for algo := range supportedAlgorithms {
		begTestCRLF := fmt.Sprintf("\r\n-----BEGIN %s SIGNATURE-----\r\n", algo)
		endTestCRLF := fmt.Sprintf("-----END %s SIGNATURE-----\r\n", algo)
		begTestLF := fmt.Sprintf("\n-----BEGIN %s SIGNATURE-----\n", algo)
		endTestLF := fmt.Sprintf("-----END %s SIGNATURE-----\n", algo)

		if strings.Contains(s, begTestCRLF) && strings.Contains(s, endTestCRLF) {
			algorithm = algo
			beg = begTestCRLF
			end = endTestCRLF
			break
		} else if strings.Contains(s, begTestLF) && strings.Contains(s, endTestLF) {
			algorithm = algo
			beg = begTestLF
			end = endTestLF
			break
		}
	}

	if algorithm == "" {
		return fmt.Errorf("no supported signature block found")
	}

	i := strings.Index(s, beg)
	j := strings.Index(s, end)
	if i == -1 || j == -1 || j <= i {
		return fmt.Errorf("invalid signature block format")
	}

	// Extract original message and signature
	originalMessage := normalizedInput[:i] // Already normalized
	hexPart := s[i+len(beg) : j]
	hexPart = regexp.MustCompile(`[\r\n\s\t]+`).ReplaceAllString(hexPart, "")

	combined, err := hex.DecodeString(hexPart)
	if err != nil {
		return fmt.Errorf("hex decode failed: %v", err)
	}

	// Display status for large documents
	if len(originalMessage) > 1024*1024 {
		g.statusLabel.SetText("Verifying large document (" + formatByteSize(len(originalMessage)) + ")...")
		g.window.Canvas().Refresh(g.statusLabel)
	}

	// Verify based on algorithm type
	switch algorithm {
	case AlgorithmED25519:
		// Ed25519 for text signature - uses hash of normalized data
		hash := sha256.Sum256(originalMessage)
		return g.verifyEd25519(hash[:], combined)
	case AlgorithmECCP256, AlgorithmECCP384:
		return g.verifyECDSA(originalMessage, combined, algorithm)
	default:
		return fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
}

// verifyEd25519 verifies an Ed25519 signature
func (g *GUI) verifyEd25519(dataHash, combined []byte) error {
	if len(combined) != Ed25519CombinedSize {
		return fmt.Errorf("invalid Ed25519 signature block")
	}

	publicKey := combined[:Ed25519PublicKeySize]
	signature := combined[Ed25519PublicKeySize:]

	// Ed25519 verifies the hash of the data (YubiKey compatibility)
	if !ed25519.Verify(ed25519.PublicKey(publicKey), dataHash, signature) {
		return fmt.Errorf("Ed25519 signature verification failed")
	}

	return nil
}

// verifyECDSA verifies an ECDSA signature
func (g *GUI) verifyECDSA(data, combined []byte, algorithm string) error {
	var curve elliptic.Curve
	var hashFunc crypto.Hash

	switch algorithm {
	case AlgorithmECCP256:
		curve = elliptic.P256()
		hashFunc = crypto.SHA256
	case AlgorithmECCP384:
		curve = elliptic.P384()
		hashFunc = crypto.SHA384
	default:
		return fmt.Errorf("unsupported ECDSA algorithm: %s", algorithm)
	}

	curveSize := (curve.Params().BitSize + 7) / 8
	expectedBytes := curveSize * 4
	if len(combined) != expectedBytes {
		return fmt.Errorf("invalid signature block size: expected %d, got %d", expectedBytes, len(combined))
	}

	// Extract public key components and signature values
	x := new(big.Int).SetBytes(combined[0:curveSize])
	y := new(big.Int).SetBytes(combined[curveSize : curveSize*2])
	r := new(big.Int).SetBytes(combined[curveSize*2 : curveSize*3])
	sVal := new(big.Int).SetBytes(combined[curveSize*3:])

	pub := &ecdsa.PublicKey{Curve: curve, X: x, Y: y}

	// Hash the data for verification
	var digest []byte
	switch hashFunc {
	case crypto.SHA256:
		h := sha256.New()
		h.Write(data)
		digest = h.Sum(nil)
	case crypto.SHA384:
		h := sha512.New384()
		h.Write(data)
		digest = h.Sum(nil)
	}

	// Verify the signature
	if !ecdsa.Verify(pub, digest, r, sVal) {
		return fmt.Errorf("signature verification failed")
	}

	return nil
}

// encryptData encrypts data using RSA-OAEP and AES-GCM
func (g *GUI) encryptData(data []byte, pubKeyFile string) (string, error) {
	pubKey, err := loadRSAPublicKey(pubKeyFile)
	if err != nil {
		return "", fmt.Errorf("failed to load public key: %v", err)
	}

	// Generate random AES key
	aesKeyGuard := memguard.NewBuffer(32)
	defer aesKeyGuard.Destroy()
	if _, err := rand.Read(aesKeyGuard.Bytes()); err != nil {
		return "", fmt.Errorf("failed to generate AES key: %v", err)
	}

	// Encrypt AES key with RSA
	encryptedKey, err := rsa.EncryptPKCS1v15(rand.Reader, pubKey, aesKeyGuard.Bytes())
	if err != nil {
		return "", fmt.Errorf("RSA encryption failed: %v", err)
	}
	defer memguard.WipeBytes(encryptedKey)

	// Encrypt data with AES
	encryptedData, err := encryptAES(data, aesKeyGuard.Bytes())
	if err != nil {
		return "", fmt.Errorf("AES encryption failed: %v", err)
	}
	defer memguard.WipeBytes(encryptedData)

	// Combine encrypted key and data
	combined := append(encryptedKey, encryptedData...)
	defer memguard.WipeBytes(combined)

	base64Str := base64.StdEncoding.EncodeToString(combined)
	return formatBase64RFC(base64Str), nil
}

// decryptData decrypts data using YubiKey's private key
func (g *GUI) decryptData(data []byte, pin string) ([]byte, error) {
	pinGuard := memguard.NewBufferFromBytes([]byte(pin))
	defer pinGuard.Destroy()

	// Clean up base64 input
	s := string(data)
	s = strings.ReplaceAll(s, "\r\n", "")
	s = strings.ReplaceAll(s, " ", "")

	combined, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("base64 decode failed: %v", err)
	}
	defer memguard.WipeBytes(combined)

	yk, err := openYubiKey(0)
	if err != nil {
		return nil, fmt.Errorf("failed to open YubiKey: %v", err)
	}
	defer yk.Close()

	// Get certificate from key management slot
	cert, err := yk.Certificate(piv.SlotKeyManagement)
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate from slot 9d: %v", err)
	}

	rsaPubKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("certificate does not contain RSA public key")
	}

	if err := checkRSASecurity(rsaPubKey, "on YubiKey"); err != nil {
		return nil, err
	}

	keySize := rsaPubKey.Size()
	if len(combined) < keySize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	// Split encrypted key and data
	encryptedKey := combined[:keySize]
	encryptedData := combined[keySize:]
	defer memguard.WipeBytes(encryptedKey)

	auth := piv.KeyAuth{PIN: pin}
	priv, err := yk.PrivateKey(piv.SlotKeyManagement, cert.PublicKey, auth)
	if err != nil {
		return nil, fmt.Errorf("failed to get private key: %v", err)
	}

	decrypter, ok := priv.(crypto.Decrypter)
	if !ok {
		return nil, fmt.Errorf("private key does not support decryption")
	}

	// Decrypt AES key with RSA
	decryptedPayload, err := decrypter.Decrypt(rand.Reader, encryptedKey, nil)
	if err != nil {
		return nil, fmt.Errorf("RSA decryption failed: %v", err)
	}
	defer memguard.WipeBytes(decryptedPayload)

	if len(decryptedPayload) != 32 {
		return nil, fmt.Errorf("invalid AES key size")
	}

	// Decrypt data with AES
	decryptedData, err := decryptAES(encryptedData, decryptedPayload)
	if err != nil {
		return nil, fmt.Errorf("AES decryption failed: %v", err)
	}

	return decryptedData, nil
}

// normalizeToRFCCompliantCRLF converts all line endings to RFC-compliant CRLF
// RFC 5322 compliant for email and Usenet
func normalizeToRFCCompliantCRLF(data []byte) []byte {
	// First convert all CRLF and single CR to LF
	s := string(data)
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	// Then convert all LF to RFC-compliant CRLF
	s = strings.ReplaceAll(s, "\n", "\r\n")
	return []byte(s)
}

// formatSignatureRFC formats hex signature with 64 characters per line and RFC-compliant CRLF
func formatSignatureRFC(sig string) string {
	var result strings.Builder
	for i := 0; i < len(sig); i += 64 {
		end := i + 64
		if end > len(sig) {
			end = len(sig)
		}
		result.WriteString(sig[i:end])
		result.WriteString("\r\n") // RFC-compliant line ending
	}
	return result.String()
}

// formatBase64RFC formats base64 string with 76 characters per line and RFC-compliant CRLF
// RFC 2045 compliant for MIME encoding
func formatBase64RFC(data string) string {
	var result strings.Builder
	for i := 0; i < len(data); i += 76 { // 76 chars per line as per RFC
		end := i + 76
		if end > len(data) {
			end = len(data)
		}
		result.WriteString(data[i:end])
		result.WriteString("\r\n") // RFC-compliant line ending
	}
	return result.String()
}

// formatByteSize formats bytes into human-readable format
func formatByteSize(bytes int) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// securePadMessage adds ISO/IEC 7816-4 padding to align data to 4096-byte blocks
func securePadMessage(data []byte) []byte {
	const blockSize = 4096
	paddingNeeded := blockSize - (len(data) % blockSize)
	if paddingNeeded == blockSize {
		return data
	}

	paddedData := make([]byte, len(data)+paddingNeeded)
	copy(paddedData, data)
	paddedData[len(data)] = 0x80
	return paddedData
}

// secureUnpadMessage removes padding added by securePadMessage
func secureUnpadMessage(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("cannot unpad empty data")
	}

	if len(data)%4096 != 0 {
		return nil, errors.New("invalid block size for unpadding")
	}

	lastIndex := -1
	for i := len(data) - 1; i >= 0; i-- {
		if data[i] == 0x80 {
			lastIndex = i
			break
		}
		if data[i] != 0x00 {
			return nil, errors.New("invalid padding format: unexpected non-zero byte")
		}
	}

	if lastIndex == -1 {
		return nil, errors.New("no padding marker found")
	}

	return data[:lastIndex], nil
}

func (g *GUI) onPad() {
	input := g.textArea.Text
	if input == "" {
		g.statusLabel.SetText("Error: No text to pad")
		return
	}

	paddedData := securePadMessage([]byte(input))
	base64String := base64.StdEncoding.EncodeToString(paddedData)
	formattedBase64 := formatBase64RFC(base64String)

	g.textArea.SetText(formattedBase64)

	originalLen := len(input)
	paddedLen := len(paddedData)
	g.statusLabel.SetText(fmt.Sprintf("✓ Padded: %d -> %d bytes (Base64)", originalLen, paddedLen))
}

func (g *GUI) onUnpad() {
	input := g.textArea.Text
	if input == "" {
		g.statusLabel.SetText("Error: No text to unpad")
		return
	}

	binaryData, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		g.statusLabel.SetText("Unpadding failed: Invalid Base64 data")
		return
	}

	unpaddedData, err := secureUnpadMessage(binaryData)
	if err != nil {
		g.statusLabel.SetText("Unpadding failed: " + err.Error())
		return
	}

	g.textArea.SetText(string(unpaddedData))
	g.statusLabel.SetText("✓ Message unpadded successfully")
}

// checkRSASecurity validates RSA key size
func checkRSASecurity(pubKey *rsa.PublicKey, context string) error {
	keySize := pubKey.N.BitLen()

	if keySize < minRSABits {
		return fmt.Errorf("insecure %d-bit RSA key %s - minimum is %d-bit", keySize, context, minRSABits)
	}

	if _, supported := supportedRSASizes[keySize]; !supported {
		fmt.Fprintf(os.Stderr, "WARNING: %d-bit RSA key %s - supported sizes are 2048, 3072, 4096 bits\n", keySize, context)
	}

	if keySize == 1024 {
		fmt.Fprintf(os.Stderr, "CRITICAL WARNING: 1024-bit RSA keys %s are insecure and should not be used!\n", context)
	}

	return nil
}

// loadRSAPublicKey loads RSA public key from PEM file
func loadRSAPublicKey(filename string) (*rsa.PublicKey, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key file: %v", err)
	}
	defer memguard.WipeBytes(data)

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM data found in file")
	}

	switch block.Type {
	case "CERTIFICATE":
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %v", err)
		}
		pubKey, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("certificate does not contain RSA public key")
		}
		if err := checkRSASecurity(pubKey, "in certificate "+filename); err != nil {
			return nil, err
		}
		return pubKey, nil

	case "PUBLIC KEY":
		pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse public key: %v", err)
		}
		pubKey, ok := pubInterface.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("not an RSA public key")
		}
		if err := checkRSASecurity(pubKey, "in file "+filename); err != nil {
			return nil, err
		}
		return pubKey, nil

	case "RSA PUBLIC KEY":
		pubKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse RSA public key: %v", err)
		}
		if err := checkRSASecurity(pubKey, "in file "+filename); err != nil {
			return nil, err
		}
		return pubKey, nil

	default:
		return nil, fmt.Errorf("unsupported PEM type: %s, expected CERTIFICATE, PUBLIC KEY or RSA PUBLIC KEY", block.Type)
	}
}

// encryptAES encrypts data using AES-256-GCM
func encryptAES(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// decryptAES decrypts data using AES-256-GCM
func decryptAES(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
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
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// openYubiKey opens a connection to the YubiKey
func openYubiKey(index int) (*piv.YubiKey, error) {
	cards, err := piv.Cards()
	if err != nil {
		return nil, fmt.Errorf("failed to list cards: %v", err)
	}
	if len(cards) == 0 {
		return nil, fmt.Errorf("no smart card found")
	}

	count := 0
	for _, card := range cards {
		if strings.Contains(strings.ToLower(card), "yubikey") {
			if count == index {
				return piv.Open(card)
			}
			count++
		}
	}
	return nil, fmt.Errorf("no YubiKey found at index %d", index)
}
