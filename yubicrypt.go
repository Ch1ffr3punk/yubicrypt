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

// Curve to algorithm mapping
var curveToAlgorithm = map[elliptic.Curve]string{
	elliptic.P256(): AlgorithmECCP256,
	elliptic.P384(): AlgorithmECCP384,
}

var curveToHash = map[elliptic.Curve]crypto.Hash{
	elliptic.P256(): crypto.SHA256,
	elliptic.P384(): crypto.SHA384,
}

// For Ed25519 - fixed sizes
const (
	Ed25519SignatureSize = 64
	Ed25519PublicKeySize = 32
	Ed25519CombinedSize  = Ed25519SignatureSize + Ed25519PublicKeySize // 96 bytes
)

const (
	minRSABits = 2048 // Minimum RSA key size accepted
)

// Supported RSA key sizes
var supportedRSASizes = map[int]string{
	2048: "RSA2048",
	3072: "RSA3072",
	4096: "RSA4096",
}

// GUI Structure
type GUI struct {
	app            fyne.App
	window         fyne.Window
	themeToggle    *widget.Button
	textArea       *widget.Entry
	pinEntry       *widget.Entry
	statusLabel    *widget.Label
	publicKeyPath  string
	currentTheme   string
	encryptionUsed bool // Flag to track if encryption was already used in this session
}

func main() {
	defer memguard.Purge()

	gui := &GUI{
		app:           app.NewWithID("oc2mx.net.yubicrypt"),
		currentTheme:  "dark",
		encryptionUsed: false,
	}

	gui.window = gui.app.NewWindow("yubicrypt")
	gui.window.Resize(fyne.NewSize(800, 600))

	gui.createUI()
	gui.applyTheme()

	gui.window.SetContent(gui.createMainUI())
	gui.window.ShowAndRun()
}

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

	// Theme Toggle Button
	g.themeToggle = widget.NewButtonWithIcon("", theme.ViewRefreshIcon(), g.toggleTheme)
}

func (g *GUI) createMainUI() fyne.CanvasObject {
	// Operation Buttons
	signBtn := widget.NewButtonWithIcon("Sign", theme.ConfirmIcon(), g.onSign)
	verifyBtn := widget.NewButtonWithIcon("Verify", theme.VisibilityIcon(), g.onVerify)
	padBtn := widget.NewButtonWithIcon("Pad", theme.ContentAddIcon(), g.onPad)
	unpadBtn := widget.NewButtonWithIcon("Unpad", theme.ContentRemoveIcon(), g.onUnpad)
	encryptBtn := widget.NewButtonWithIcon("Encrypt", theme.MailComposeIcon(), g.onEncrypt)
	decryptBtn := widget.NewButtonWithIcon("Decrypt", theme.MailForwardIcon(), g.onDecrypt)

	// Button Container
	buttonContainer := container.NewHBox(
		layout.NewSpacer(),
		signBtn,
		verifyBtn,
		padBtn,
		unpadBtn,
		encryptBtn,
		decryptBtn,
		layout.NewSpacer(),
	)

	clearBtn := widget.NewButtonWithIcon("Clear", theme.DeleteIcon(), g.onClear)
	pinContainer := container.NewHBox(
		widget.NewLabel("PIN:"),
		g.pinEntry,
		clearBtn,
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

func (g *GUI) applyTheme() {
	if g.currentTheme == "dark" {
		g.app.Settings().SetTheme(theme.DarkTheme())
	} else {
		g.app.Settings().SetTheme(theme.LightTheme())
	}
}

func (g *GUI) onSign() {
	if g.pinEntry.Text == "" {
		g.statusLabel.SetText("Error: PIN required for signing")
		return
	}

	input := g.textArea.Text
	if input == "" {
		g.statusLabel.SetText("Error: No text to sign")
		return
	}

	result, err := g.signData([]byte(input), g.pinEntry.Text)
	if err != nil {
		g.statusLabel.SetText("Signing failed: " + err.Error())
		return
	}

	g.textArea.SetText(result)
	g.statusLabel.SetText("✓ Message signed successfully")
}

func (g *GUI) onVerify() {
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

func (g *GUI) onEncrypt() {
	// If encryption was already used in this session, require new certificate
	if g.encryptionUsed {
		g.statusLabel.SetText("Please select a new certificate for encryption.")
		g.publicKeyPath = "" // Reset public key path to force new selection
		g.choosePublicKey()
		return
	}

	// If certificate already selected, encrypt immediately
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

	// No certificate selected yet, open file dialog
	g.choosePublicKey()
}

func (g *GUI) choosePublicKey() {
	dialog.ShowFileOpen(func(reader fyne.URIReadCloser, err error) {
		if err != nil {
			g.statusLabel.SetText("Error selecting file: " + err.Error())
			return
		}
		if reader == nil {
			return // Dialog cancelled
		}
		defer reader.Close()

		path := reader.URI().Path()
		if filepath.Ext(path) != ".pem" {
			g.statusLabel.SetText("Error: Please select a .pem file")
			return
		}

		g.publicKeyPath = path
		g.encryptionUsed = false // Reset encryption flag when new certificate is selected
		g.statusLabel.SetText("Selected public key: " + filepath.Base(path) + " - Encrypting...")

		// AUTOMATIC ENCRYPTION AFTER CERTIFICATE SELECTION - LIKE GNUPG/AGE
		input := g.textArea.Text
		if input == "" {
			g.statusLabel.SetText("Selected: " + filepath.Base(path) + " - No text to encrypt")
			return
		}

		result, err := g.encryptData([]byte(input), g.publicKeyPath)
		if err != nil {
			g.statusLabel.SetText("Encryption failed: " + err.Error())
			return
		}

		// Mark encryption as used for this session
		g.encryptionUsed = true
		g.textArea.SetText(result)
		g.statusLabel.SetText("✓ Encrypted with: " + filepath.Base(path))
	}, g.window)
}

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

func (g *GUI) onClear() {
	g.textArea.SetText("")
	g.publicKeyPath = ""
	g.encryptionUsed = false // Reset encryption state on clear

	clipboard := g.app.Clipboard()
	if clipboard != nil {
		clipboard.SetContent("")
	}

	g.statusLabel.SetText("Cleared text area, clipboard and reset encryption state")
}

// signData signs with RFC-compliant normalization
func (g *GUI) signData(data []byte, pin string) (string, error) {
    pinGuard := memguard.NewBufferFromBytes([]byte(pin))
    defer pinGuard.Destroy()

    // Normalize to RFC-compliant CRLF before signing
    normalizedData := normalizeToRFCCompliantCRLF(data)
    
    sig, curveType, err := g.signDataInternal(pinGuard.Bytes(), normalizedData)
    if err != nil {
        return "", fmt.Errorf("signing failed: %v", err)
    }

    // RFC-compliant signature block
    return string(normalizedData) + "\r\n-----BEGIN " + curveType + " SIGNATURE-----\r\n" +
        formatSignature(sig) + "-----END " + curveType + " SIGNATURE-----\r\n", nil
}

// signDataInternal performs the actual signing operation with the YubiKey
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

	// Check for Ed25519 support
	if ed25519PubKey, ok := cert.PublicKey.(ed25519.PublicKey); ok {
		return g.signDataEd25519(pin, data, ed25519PubKey, yk)
	}

	// ECDSA support
	pubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return "", "", fmt.Errorf("public key is not ECDSA or Ed25519")
	}

	// Determine curve type
	algorithm, exists := curveToAlgorithm[pubKey.Curve]
	if !exists {
		return "", "", fmt.Errorf("unsupported curve: %v", pubKey.Curve)
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

	// Use appropriate hash for the curve
	hashFunc := curveToHash[pubKey.Curve]
	var digest []byte

	switch hashFunc {
	case crypto.SHA256:
		h := sha256.Sum256(data)
		digest = h[:]
	case crypto.SHA384:
		h := sha512.Sum384(data)
		digest = h[:]
	default:
		return "", "", fmt.Errorf("unsupported hash algorithm for curve")
	}

	asn1sig, err := signer.Sign(rand.Reader, digest, hashFunc)
	if err != nil {
		return "", "", fmt.Errorf("ECDSA signing failed: %v", err)
	}

	var sig ecSignature
	if _, err := asn1.Unmarshal(asn1sig, &sig); err != nil {
		return "", "", fmt.Errorf("ASN.1 unmarshal failed: %v", err)
	}

	// Calculate appropriate padding based on curve
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

// signDataEd25519 handles Ed25519 signing operations
func (g *GUI) signDataEd25519(pin, data []byte, pubKey ed25519.PublicKey, yk *piv.YubiKey) (string, string, error) {
	auth := piv.KeyAuth{PIN: string(pin)}
	priv, err := yk.PrivateKey(piv.SlotSignature, pubKey, auth)
	if err != nil {
		return "", "", fmt.Errorf("failed to get private key: %v", err)
	}

	signer, ok := priv.(crypto.Signer)
	if !ok {
		return "", "", fmt.Errorf("key does not implement crypto.Signer")
	}

	signature, err := signer.Sign(rand.Reader, data, crypto.Hash(0))
	if err != nil {
		return "", "", fmt.Errorf("Ed25519 signing failed: %v", err)
	}

	combined := append(signature, pubKey...)
	return hex.EncodeToString(combined), AlgorithmED25519, nil
}

// verifyData handles verification with proper message normalization
func (g *GUI) verifyData(data []byte) error {
    s := string(data)

    // Strict RFC-compliant detection - only CRLF format accepted
    var algorithm string
    var beg, end string

    for algo := range supportedAlgorithms {
        begTest := fmt.Sprintf("\r\n-----BEGIN %s SIGNATURE-----\r\n", algo)
        endTest := fmt.Sprintf("-----END %s SIGNATURE-----\r\n", algo)

        if strings.Contains(s, begTest) && strings.Contains(s, endTest) {
            algorithm = algo
            beg = begTest
            end = endTest
            break
        }
    }

    if algorithm == "" {
        // Try without CRLF in case of Usenet/email
        for algo := range supportedAlgorithms {
            begTest := fmt.Sprintf("-----BEGIN %s SIGNATURE-----", algo)
            endTest := fmt.Sprintf("-----END %s SIGNATURE-----", algo)

            if strings.Contains(s, begTest) && strings.Contains(s, endTest) {
                algorithm = algo
                beg = begTest
                end = endTest
                break
            }
        }
        
        if algorithm == "" {
            return fmt.Errorf("no supported signature block found")
        }
    }

    i := strings.Index(s, beg)
    j := strings.Index(s, end)

    if i == -1 || j == -1 || j < i {
        return fmt.Errorf("invalid signature block format")
    }

    // Extract original message
    originalMessage := []byte(s[:i])
    hexPart := s[i+len(beg):j]
    
    // Remove all line breaks and whitespace from hex part
    hexPart = strings.ReplaceAll(hexPart, "\r\n", "")
    hexPart = strings.ReplaceAll(hexPart, "\n", "")
    hexPart = strings.ReplaceAll(hexPart, "\r", "")
    hexPart = strings.ReplaceAll(hexPart, " ", "")
    hexPart = strings.ReplaceAll(hexPart, "\t", "")

    combined, err := hex.DecodeString(hexPart)
    if err != nil {
        return fmt.Errorf("hex decode failed: %v", err)
    }

    // Normalize ONLY the message part for verification
    normalizedMessage := normalizeToRFCCompliantCRLF(originalMessage)

    switch algorithm {
    case AlgorithmED25519:
        return g.verifyEd25519(normalizedMessage, combined)
    case AlgorithmECCP256, AlgorithmECCP384:
        return g.verifyECDSA(normalizedMessage, combined, algorithm)
    default:
        return fmt.Errorf("unsupported algorithm: %s", algorithm)
    }
}

// verifyEd25519 verifies Ed25519 signatures
func (g *GUI) verifyEd25519(data, combined []byte) error {
	if len(combined) != Ed25519CombinedSize {
		return fmt.Errorf("invalid Ed25519 signature block")
	}

	signature := combined[:Ed25519SignatureSize]
	publicKey := combined[Ed25519SignatureSize:]

	if !ed25519.Verify(publicKey, data, signature) {
		return fmt.Errorf("Ed25519 signature verification failed")
	}

	return nil
}

// verifyECDSA verifies ECDSA signatures
func (g *GUI) verifyECDSA(data, combined []byte, algorithm string) error {
	var curve elliptic.Curve
	switch algorithm {
	case AlgorithmECCP256:
		curve = elliptic.P256()
	case AlgorithmECCP384:
		curve = elliptic.P384()
	default:
		return fmt.Errorf("unsupported ECDSA algorithm: %s", algorithm)
	}

	curveSize := (curve.Params().BitSize + 7) / 8
	expectedBytes := curveSize * 4

	if len(combined) != expectedBytes {
		return fmt.Errorf("invalid signature block size")
	}

	x := new(big.Int).SetBytes(combined[0:curveSize])
	y := new(big.Int).SetBytes(combined[curveSize:curveSize*2])
	r := new(big.Int).SetBytes(combined[curveSize*2:curveSize*3])
	sVal := new(big.Int).SetBytes(combined[curveSize*3:curveSize*4])

	pub := &ecdsa.PublicKey{Curve: curve, X: x, Y: y}

	hashFunc := curveToHash[curve]
	var digest []byte

	switch hashFunc {
	case crypto.SHA256:
		h := sha256.Sum256(data)
		digest = h[:]
	case crypto.SHA384:
		h := sha512.Sum384(data)
		digest = h[:]
	default:
		return fmt.Errorf("unsupported hash algorithm")
	}

	if !ecdsa.Verify(pub, digest, r, sVal) {
		return fmt.Errorf("signature is not valid")
	}

	return nil
}

// encryptData encrypts data using RSA public key and AES encryption
func (g *GUI) encryptData(data []byte, pubKeyFile string) (string, error) {
	pubKey, err := loadRSAPublicKey(pubKeyFile)
	if err != nil {
		return "", fmt.Errorf("failed to load public key: %v", err)
	}

	// Generate AES key - will be automatically cleaned up by memguard
	aesKeyGuard := memguard.NewBuffer(32)
	defer aesKeyGuard.Destroy() // Secure cleanup after use
	if _, err := rand.Read(aesKeyGuard.Bytes()); err != nil {
		return "", fmt.Errorf("failed to generate AES key: %v", err)
	}

	// Encrypt AES key with RSA public key
	encryptedKey, err := rsa.EncryptPKCS1v15(rand.Reader, pubKey, aesKeyGuard.Bytes())
	if err != nil {
		return "", fmt.Errorf("RSA encryption failed: %v", err)
	}
	defer memguard.WipeBytes(encryptedKey)

	// Encrypt data with AES key
	encryptedData, err := encryptAES(data, aesKeyGuard.Bytes())
	if err != nil {
		return "", fmt.Errorf("AES encryption failed: %v", err)
	}
	defer memguard.WipeBytes(encryptedData)

	// Combine encrypted key and data
	combined := append(encryptedKey, encryptedData...)
	defer memguard.WipeBytes(combined)

	base64Str := base64.StdEncoding.EncodeToString(combined)
	return formatBase64(base64Str), nil
}

// decryptData decrypts data using YubiKey's RSA private key
func (g *GUI) decryptData(data []byte, pin string) ([]byte, error) {
	pinGuard := memguard.NewBufferFromBytes([]byte(pin))
	defer pinGuard.Destroy()

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

	decryptedPayload, err := decrypter.Decrypt(rand.Reader, encryptedKey, nil)
	if err != nil {
		return nil, fmt.Errorf("RSA decryption failed: %v", err)
	}
	defer memguard.WipeBytes(decryptedPayload)

	if len(decryptedPayload) != 32 {
		return nil, fmt.Errorf("invalid AES key size")
	}

	decryptedData, err := decryptAES(encryptedData, decryptedPayload)
	if err != nil {
		return nil, fmt.Errorf("AES decryption failed: %v", err)
	}

	return decryptedData, nil
}

// normalizeToRFCCompliantCRLF normalizes all line endings to RFC-compliant CRLF
// and ensures proper line length for cryptographic operations
func normalizeToRFCCompliantCRLF(data []byte) []byte {
    s := string(data)
    
    // First convert all line endings to LF
    s = strings.ReplaceAll(s, "\r\n", "\n")
    s = strings.ReplaceAll(s, "\r", "\n")
    
    // Now convert to RFC-compliant CRLF
    lines := strings.Split(s, "\n")
    var result strings.Builder
    
    for _, line := range lines {
        trimmed := strings.TrimSpace(line)
        if trimmed != "" {
            result.WriteString(trimmed)
            result.WriteString("\r\n")
        }
    }
    
    return []byte(result.String())
}

// normalizeMessageOnly normalizes only the message part, preserves signature blocks
func normalizeMessageOnly(data []byte) []byte {
    s := string(data)
    
    // Check if we have a signature block
    var signatureStart, signatureEnd int = -1, -1
        
    for algo := range supportedAlgorithms {
        begTest := fmt.Sprintf("-----BEGIN %s SIGNATURE-----", algo)
        endTest := fmt.Sprintf("-----END %s SIGNATURE-----", algo)
        
        if start := strings.Index(s, begTest); start != -1 {
            if end := strings.Index(s, endTest); end != -1 && end > start {
                signatureStart = start
                signatureEnd = end + len(endTest)
                _ = algo
                break
            }
        }
    }
    
    if signatureStart == -1 {
        // No signature found, normalize entire content
        return normalizeToRFCCompliantCRLF(data)
    }
    
    // Extract message part (before signature)
    messagePart := s[:signatureStart]
    
    // Normalize only the message part
    normalizedMessage := normalizeToRFCCompliantCRLF([]byte(messagePart))
    
    // Keep signature block unchanged
    signatureBlock := s[signatureStart:signatureEnd]
    
    // Reconstruct with normalized message and original signature
    return append(normalizedMessage, []byte(signatureBlock)...)
}

// formatSignature creates RFC-compliant signature with 64 characters per line and CRLF
func formatSignature(sig string) string {
    var result strings.Builder
    for i := 0; i < len(sig); i += 64 {
        end := i + 64
        if end > len(sig) {
            end = len(sig)
        }
        result.WriteString(sig[i:end])
        result.WriteString("\r\n") // RFC-compliant CRLF
    }
    return result.String()
}

// formatBase64 formats base64 string with 76 characters per line
func formatBase64(data string) string {
	var result strings.Builder
	for i := 0; i < len(data); i += 76 {
		end := i + 76
		if end > len(data) {
			end = len(data)
		}
		result.WriteString(data[i:end])
		result.WriteString("\r\n")
	}
	return result.String()
}

// securePadMessage adds cryptographic padding to the message
func securePadMessage(data []byte) (string, error) {
	const blockSize = 4096
	const minSize = 4096
	const lineLength = 76

	if len(data) == 0 {
		return "", errors.New("empty data cannot be padded")
	}

	// Preserve original text with line breaks intact
	originalText := string(data)
	currentSize := len(originalText)

	// Determine target size
	var targetSize int
	if currentSize < minSize {
		targetSize = minSize
	} else {
		targetSize = ((currentSize/blockSize) + 1) * blockSize
	}

	// Length information - IMPORTANT: length of ORIGINAL text
	lengthInfo := fmt.Sprintf("===LENGTH:%d===", len(originalText))
	totalMarkerLength := len("===PADDING===") + len(lengthInfo)
	paddingNeeded := targetSize - currentSize - totalMarkerLength

	if paddingNeeded < 0 {
		targetSize += blockSize
		paddingNeeded = targetSize - currentSize - totalMarkerLength
	}

	// Generate random padding
	randomBytes := make([]byte, (paddingNeeded+1)/2)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("error generating random padding: %v", err)
	}

	randomHex := hex.EncodeToString(randomBytes)
	if len(randomHex) > paddingNeeded {
		randomHex = randomHex[:paddingNeeded]
	}

	// Append padding at the END (after signature) and format it properly
	paddingContent := "===PADDING===" + randomHex + lengthInfo
	formattedPadding := formatTo76Chars(paddingContent)

	// Combine original text with formatted padding
	paddedContent := originalText + formattedPadding

	return paddedContent, nil
}

// secureUnpadMessage removes cryptographic padding from the message
func secureUnpadMessage(data string) ([]byte, error) {
	if data == "" {
		return []byte{}, nil
	}

	// Search for padding marker in the original formatted text
	paddingIndex := strings.Index(data, "===PADDING===")
	if paddingIndex == -1 {
		// No padding found, return original text with all formatting
		return []byte(data), nil
	}

	// Return everything before the padding marker (preserves signature structure)
	return []byte(data[:paddingIndex]), nil
}

// formatTo76Chars formats text to 76 characters per line with CRLF
func formatTo76Chars(text string) string {
	const lineLength = 76
	var result strings.Builder

	// Remove existing line breaks first to avoid double formatting
	cleanText := strings.ReplaceAll(text, "\r\n", "")
	cleanText = strings.ReplaceAll(cleanText, "\n", "")

	for i := 0; i < len(cleanText); i += lineLength {
		end := i + lineLength
		if end > len(cleanText) {
			end = len(cleanText)
		}
		result.WriteString(cleanText[i:end])
		result.WriteString("\r\n")
	}
	return result.String()
}

func (g *GUI) onPad() {
	input := g.textArea.Text
	if input == "" {
		g.statusLabel.SetText("Error: No text to pad")
		return
	}

	result, err := securePadMessage([]byte(input))
	if err != nil {
		g.statusLabel.SetText("Padding failed: %v")
		return
	}

	g.textArea.SetText(result)

	// Show padding statistics
	originalLen := len(input)
	paddedLen := len(result)
	lines := strings.Count(result, "\r\n") + 1
	g.statusLabel.SetText(fmt.Sprintf("✓ Padded: %d → %d bytes (%d lines)",
		originalLen, paddedLen, lines))
}

func (g *GUI) onUnpad() {
	input := g.textArea.Text
	if input == "" {
		g.statusLabel.SetText("Error: No text to unpad")
		return
	}

	result, err := secureUnpadMessage(input)
	if err != nil {
		g.statusLabel.SetText("Unpadding failed: %v")
		return
	}

	g.textArea.SetText(string(result))
	g.statusLabel.SetText("✓ Message unpadded successfully")
}

// checkRSASecurity checks RSA key length and issues warnings/errors
func checkRSASecurity(pubKey *rsa.PublicKey, context string) error {
	keySize := pubKey.N.BitLen()

	if keySize < minRSABits {
		return fmt.Errorf("insecure %d-bit RSA key %s - minimum is %d-bit", keySize, context, minRSABits)
	}

	// Check if key size is supported
	if _, supported := supportedRSASizes[keySize]; !supported {
		fmt.Fprintf(os.Stderr, "WARNING: %d-bit RSA key %s - supported sizes are 2048, 3072, 4096 bits\n",
			keySize, context)
	}

	if keySize == 1024 {
		fmt.Fprintf(os.Stderr, "CRITICAL WARNING: 1024-bit RSA keys %s are insecure and should not be used!\n", context)
	}

	return nil
}

// loadRSAPublicKey loads an RSA public key from a PEM file
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
		// Security check for certificate
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
		// Security check for public key
		if err := checkRSASecurity(pubKey, "in file "+filename); err != nil {
			return nil, err
		}
		return pubKey, nil

	case "RSA PUBLIC KEY":
		pubKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse RSA public key: %v", err)
		}
		// Security check for RSA public key
		if err := checkRSASecurity(pubKey, "in file "+filename); err != nil {
			return nil, err
		}
		return pubKey, nil

	default:
		return nil, fmt.Errorf("unsupported PEM type: %s, expected CERTIFICATE, PUBLIC KEY or RSA PUBLIC KEY", block.Type)
	}
}

// encryptAES encrypts data using AES-GCM
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

// decryptAES decrypts data using AES-GCM
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
