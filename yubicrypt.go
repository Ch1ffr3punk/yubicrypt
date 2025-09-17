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
	"image"
	"image/color"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
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

// Mapping from elliptic curve to YOUR algorithm name (not default)
var curveToAlgorithm = map[elliptic.Curve]string{
	elliptic.P256(): AlgorithmECCP256,
	elliptic.P384(): AlgorithmECCP384,
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
	g.pinEntry.SetPlaceHolder("")
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
	signTextBtn := widget.NewButtonWithIcon("Sign", theme.ConfirmIcon(), g.onSignText)
	verifyTextBtn := widget.NewButtonWithIcon("Verify", theme.VisibilityIcon(), g.onVerifyText)

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

// safePad ensures byte slice is exactly 'size' bytes long, padded with leading zeros.
func safePad(b []byte, size int) []byte {
	if len(b) > size {
		return b[len(b)-size:] // Truncate from left if too long
	}
	return append(make([]byte, size-len(b)), b...) // Pad with leading zeros
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

	// Ensure clean separation with CRLF
	sep := "\r\n"
	if len(normalizedData) > 0 {
		last := string(normalizedData[len(normalizedData)-1:])
		if last == "\n" && !(len(normalizedData) >= 2 && string(normalizedData[len(normalizedData)-2:]) == "\r\n") {
			sep = "\n"
		}
	}

	return string(normalizedData) + sep +
		"-----BEGIN " + algo + " SIGNATURE-----" + sep +
		formatSignatureRFC(sig) +
		"-----END " + algo + " SIGNATURE-----" + sep, nil
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

	// Algorithm name is "ECCP256", not "P-256"
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

	// Build combined signature: X || Y || R || S (all padded to curveSize)
	var raw []byte
	raw = append(raw, safePad(pubKey.X.Bytes(), curveSize)...)
	raw = append(raw, safePad(pubKey.Y.Bytes(), curveSize)...)
	raw = append(raw, safePad(sig.R.Bytes(), curveSize)...)
	raw = append(raw, safePad(sig.S.Bytes(), curveSize)...)

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
	// Normalize input to handle both LF and CRLF
	s := string(normalizeToRFCCompliantCRLF(data))

	var algorithm string
	var beg, end string

	// Try to find BEGIN/END block with CRLF or LF
	for algo := range supportedAlgorithms {
		begCRLF := "\r\n-----BEGIN " + algo + " SIGNATURE-----\r\n"
		endCRLF := "-----END " + algo + " SIGNATURE-----\r\n"
		begLF := "\n-----BEGIN " + algo + " SIGNATURE-----\n"
		endLF := "-----END " + algo + " SIGNATURE-----\n"

		if strings.Contains(s, begCRLF) {
			algorithm = algo
			beg = begCRLF
			end = endCRLF
			break
		} else if strings.Contains(s, begLF) {
			algorithm = algo
			beg = begLF
			end = endLF
			break
		}
	}

	if algorithm == "" {
		g.showErrorPopup("No supported signature found", []byte{}, "")
		return fmt.Errorf("no supported signature block found")
	}

	i := strings.Index(s, beg)
	j := strings.Index(s, end)
	if i == -1 || j == -1 || j <= i {
		g.showErrorPopup("Invalid signature format", []byte{}, algorithm)
		return fmt.Errorf("invalid signature block format")
	}

	originalMessage := []byte(s[:i])
	hexPart := s[i+len(beg) : j]
	hexPart = regexp.MustCompile(`[\r\n\s\t]+`).ReplaceAllString(hexPart, "")

	combined, err := hex.DecodeString(hexPart)
	if err != nil {
		g.showErrorPopup("Hex decoding failed", []byte{}, algorithm)
		return fmt.Errorf("hex decode failed: %v", err)
	}

	// Status for large files
	if len(originalMessage) > 1024*1024 {
		g.statusLabel.SetText("Verifying large document (" + formatByteSize(len(originalMessage)) + ")...")
		g.window.Canvas().Refresh(g.statusLabel)
	}

	var verificationErr error
	switch algorithm {
	case AlgorithmED25519:
		hash := sha256.Sum256(originalMessage)
		verificationErr = g.verifyEd25519(hash[:], combined)
	case AlgorithmECCP256, AlgorithmECCP384:
		verificationErr = g.verifyECDSA(originalMessage, combined, algorithm)
	default:
		verificationErr = fmt.Errorf("unsupported algorithm: %s", algorithm)
	}

	if verificationErr != nil {
		publicKeyBytes, _ := extractPublicKeyFromSignature(combined, algorithm)
		g.showErrorPopup("Signature verification failed: "+verificationErr.Error(), publicKeyBytes, algorithm)
		return verificationErr
	}

	publicKeyBytes, err := extractPublicKeyFromSignature(combined, algorithm)
	if err != nil {
		g.showErrorPopup("Error extracting public key: "+err.Error(), []byte{}, algorithm)
		return err
	}

	// Successfully verified - show identicon from public key (hashed!)
	g.showSuccessPopup(publicKeyBytes, algorithm)
	return nil
}

// extractPublicKeyFromSignature extracts the public key from the signature
func extractPublicKeyFromSignature(combined []byte, algorithm string) ([]byte, error) {
	switch algorithm {
	case AlgorithmED25519:
		if len(combined) != Ed25519CombinedSize {
			return nil, fmt.Errorf("invalid Ed25519 signature block")
		}
		// Return only the public key (first 32 bytes)
		return combined[:Ed25519PublicKeySize], nil
		
	case AlgorithmECCP256, AlgorithmECCP384:
		var curve elliptic.Curve
		switch algorithm {
		case AlgorithmECCP256:
			curve = elliptic.P256()
		case AlgorithmECCP384:
			curve = elliptic.P384()
		default:
			return nil, fmt.Errorf("unsupported ECDSA algorithm: %s", algorithm)
		}
		
		curveSize := (curve.Params().BitSize + 7) / 8
		expectedBytes := 4 * curveSize
		if len(combined) != expectedBytes {
			return nil, fmt.Errorf("invalid signature block size: expected %d, got %d", expectedBytes, len(combined))
		}
		
		// Return only the public key (X || Y)
		return combined[:2*curveSize], nil
		
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
}

// verifyEd25519 verifies an Ed25519 signature
func (g *GUI) verifyEd25519(dataHash, combined []byte) error {
	if len(combined) != Ed25519CombinedSize {
		return fmt.Errorf("invalid Ed25519 signature block")
	}

	publicKey := combined[:Ed25519PublicKeySize]
	signature := combined[Ed25519PublicKeySize:]

	if !ed25519.Verify(ed25519.PublicKey(publicKey), dataHash, signature) {
		return fmt.Errorf("Ed25519 signature verification failed")
	}

	return nil
}

// verifyECDSA verifies an ECDSA signature with embedded public key (X,Y)
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
	expectedBytes := 4 * curveSize
	if len(combined) != expectedBytes {
		return fmt.Errorf("invalid signature block size: expected %d, got %d", expectedBytes, len(combined))
	}

	X := new(big.Int).SetBytes(safePad(combined[0:curveSize], curveSize))
	Y := new(big.Int).SetBytes(safePad(combined[curveSize:2*curveSize], curveSize))
	R := new(big.Int).SetBytes(safePad(combined[2*curveSize:3*curveSize], curveSize))
	S := new(big.Int).SetBytes(safePad(combined[3*curveSize:], curveSize))

	if !curve.IsOnCurve(X, Y) {
		return fmt.Errorf("public key point (X,Y) is not on the curve %s", curve.Params().Name)
	}

	pub := &ecdsa.PublicKey{
		Curve: curve,
		X:     X,
		Y:     Y,
	}

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

	if !ecdsa.Verify(pub, digest, R, S) {
		return fmt.Errorf("signature verification failed")
	}

	return nil
}

// stripLeadingZeros removes leading zero bytes, but keeps at least one byte.
func stripLeadingZeros(b []byte) []byte {
	i := 0
	for i < len(b)-1 && b[i] == 0 {
		i++
	}
	return b[i:]
}

// extractPublicKeyDisplayBytes returns the public key bytes for display/hashing —
// with leading zeros stripped from X and Y for ECC keys (for cleaner hex strings),
// but full raw bytes for Ed25519.
func extractPublicKeyDisplayBytes(combined []byte, algorithm string) ([]byte, error) {
	switch algorithm {
	case AlgorithmED25519:
		if len(combined) != Ed25519CombinedSize {
			return nil, fmt.Errorf("invalid Ed25519 signature block")
		}
		// Return full 32 bytes — no stripping
		return combined[:Ed25519PublicKeySize], nil

	case AlgorithmECCP256, AlgorithmECCP384:
		var curve elliptic.Curve
		switch algorithm {
		case AlgorithmECCP256:
			curve = elliptic.P256()
		case AlgorithmECCP384:
			curve = elliptic.P384()
		default:
			return nil, fmt.Errorf("unsupported ECDSA algorithm: %s", algorithm)
		}

		curveSize := (curve.Params().BitSize + 7) / 8
		expectedBytes := 4 * curveSize
		if len(combined) != expectedBytes {
			return nil, fmt.Errorf("invalid signature block size: expected %d, got %d", expectedBytes, len(combined))
		}

		// Extract X and Y with leading zeros (as stored)
		XBytes := combined[0:curveSize]
		YBytes := combined[curveSize : 2*curveSize]

		// Strip leading zeros for display — but keep at least one byte!
		XStripped := stripLeadingZeros(XBytes)
		YStripped := stripLeadingZeros(YBytes)

		// Concatenate stripped X and Y for display/hashing
		result := make([]byte, 0, len(XStripped)+len(YStripped))
		result = append(result, XStripped...)
		result = append(result, YStripped...)

		return result, nil

	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
}

// showSuccessPopup shows the identicon popup for successful verification
func (g *GUI) showSuccessPopup(publicKeyBytes []byte, algorithm string) {
	displayBytes, err := extractPublicKeyDisplayBytes(publicKeyBytes, algorithm)
	if err != nil {
		displayBytes = publicKeyBytes
	}

	hexString := hex.EncodeToString(displayBytes)
	hash := sha256.Sum256([]byte(hexString))

	identicon := NewClassicIdenticon(hash[:])
	img := identicon.Generate()

	fyneImg := canvas.NewImageFromImage(img)
	fyneImg.FillMode = canvas.ImageFillContain
	fyneImg.SetMinSize(fyne.NewSize(128, 128))

	successLabel := widget.NewLabel("Signature is valid")
	successLabel.Alignment = fyne.TextAlignCenter

	copyBtn := widget.NewButton("Copy Signature Component", func() {
		clipboard := g.app.Clipboard()
		if clipboard != nil {
			clipboard.SetContent(hexString)
			g.statusLabel.SetText("✓ Signature Component copied to clipboard")
			time.AfterFunc(2*time.Second, func() {
				g.statusLabel.SetText("Ready")
			})
		}
	})

	content := container.NewVBox(
		container.NewCenter(fyneImg),
		container.NewCenter(successLabel),
		container.NewCenter(copyBtn),
	)

	d := dialog.NewCustom("", "OK", content, g.window)
	d.Show()

}

// showErrorPopup shows an error popup with identicon for failed verification
func (g *GUI) showErrorPopup(message string, publicKeyBytes []byte, algorithm string) {
	if len(publicKeyBytes) == 0 {
		errorLabel := widget.NewLabel(message)
		errorLabel.Alignment = fyne.TextAlignCenter
		content := container.NewVBox(container.NewCenter(errorLabel))
		d := dialog.NewCustom("", "OK", content, g.window)
		d.Show()
		return
	}

	//d := dialog.NewCustom("", "OK", g.window)
	//d.Show()
}

// encryptData encrypts data using RSA-OAEP and AES-GCM
func (g *GUI) encryptData(data []byte, pubKeyFile string) (string, error) {
	pubKey, err := loadRSAPublicKey(pubKeyFile)
	if err != nil {
		return "", fmt.Errorf("failed to load public key: %v", err)
	}

	aesKeyGuard := memguard.NewBuffer(32)
	defer aesKeyGuard.Destroy()
	if _, err := rand.Read(aesKeyGuard.Bytes()); err != nil {
		return "", fmt.Errorf("failed to generate AES key: %v", err)
	}

	encryptedKey, err := rsa.EncryptPKCS1v15(rand.Reader, pubKey, aesKeyGuard.Bytes())
	if err != nil {
		return "", fmt.Errorf("RSA encryption failed: %v", err)
	}
	defer memguard.WipeBytes(encryptedKey)

	encryptedData, err := encryptAES(data, aesKeyGuard.Bytes())
	if err != nil {
		return "", fmt.Errorf("AES encryption failed: %v", err)
	}
	defer memguard.WipeBytes(encryptedData)

	combined := append(encryptedKey, encryptedData...)
	defer memguard.WipeBytes(combined)

	base64Str := base64.StdEncoding.EncodeToString(combined)
	return formatBase64RFC(base64Str), nil
}

// decryptData decrypts data using YubiKey's private key
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

// normalizeToRFCCompliantCRLF converts all line endings to RFC-compliant CRLF
func normalizeToRFCCompliantCRLF(data []byte) []byte {
	s := string(data)
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
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
		result.WriteString("\r\n")
	}
	return result.String()
}

// formatBase64RFC formats base64 string with 76 characters per line and RFC-compliant CRLF
func formatBase64RFC(data string) string {
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

// ClassicIdenticon with 100% deterministic, bit-perfect design + 2-color mode
type ClassicIdenticon struct {
	source []byte
	size   int
}

// NewClassicIdenticon creates a generator with classic look
func NewClassicIdenticon(source []byte) *ClassicIdenticon {
	return &ClassicIdenticon{
		source: source,
		size:   256,
	}
}

// mapValue maps a value from one range to another
func mapValue(value uint32, vmin, vmax, dmin, dmax uint32) float32 {
	if vmax == vmin {
		return float32(dmin)
	}
	return float32(dmin) + float32(value-vmin)*float32(dmax-dmin)/float32(vmax-vmin)
}

// getBit returns the n-th bit (0-indexed) from source
func (identicon *ClassicIdenticon) getBit(n int) bool {
	if len(identicon.source) == 0 || n < 0 {
		return false
	}
	byteIndex := n / 8
	bitIndex := n % 8
	if byteIndex >= len(identicon.source) {
		return false
	}
	return (identicon.source[byteIndex]>>bitIndex)&1 == 1
}

// getByte returns the n-th byte, wraps around if needed
func (identicon *ClassicIdenticon) getByte(n int) byte {
	if len(identicon.source) == 0 {
		return 0
	}
	return identicon.source[n%len(identicon.source)]
}

// foreground computes primary color
func (identicon *ClassicIdenticon) foreground() color.Color {
	if len(identicon.source) < 32 {
		return color.RGBA{0, 0, 0, 255}
	}

	// Use bit 255 to decide: 0 → original HSL, 1 → palette
	if !identicon.getBit(255) {
		// Original HSL algorithm — soft and harmonious
		h1 := (uint16(identicon.getByte(28)) & 0x0f) << 8
		h2 := uint16(identicon.getByte(29))
		h := uint32(h1 | h2)
		s := uint32(identicon.getByte(30))
		l := uint32(identicon.getByte(31))

		hue := mapValue(h, 0, 4095, 0, 360)
		sat := mapValue(s, 0, 255, 0, 20)
		lum := mapValue(l, 0, 255, 0, 20)

		return identicon.hslToRgb(hue, 65.0-sat, 75.0-lum)
	}

	// Vibrant color palette — 16 beautiful, distinct colors
	palette := []color.RGBA{
		{0x00, 0xbf, 0x93, 0xff}, // turquoise
		{0x2d, 0xcc, 0x70, 0xff}, // mint
		{0x42, 0xe4, 0x53, 0xff}, // green
		{0xf1, 0xc4, 0x0f, 0xff}, // yellowOrange
		{0xe6, 0x7f, 0x22, 0xff}, // brown
		{0xff, 0x94, 0x4e, 0xff}, // orange
		{0xe8, 0x4c, 0x3d, 0xff}, // red
		{0x35, 0x98, 0xdb, 0xff}, // blue
		{0x9a, 0x59, 0xb5, 0xff}, // purple
		{0xef, 0x3e, 0x96, 0xff}, // magenta
		{0xdf, 0x21, 0xb9, 0xff}, // violet
		{0x7d, 0xc2, 0xd2, 0xff}, // lightBlue
		{0x16, 0xa0, 0x86, 0xff}, // turquoiseIntense
		{0x27, 0xae, 0x61, 0xff}, // mintIntense
		{0x24, 0xc3, 0x33, 0xff}, // greenIntense
		{0x1c, 0xab, 0xbb, 0xff}, // lightBlueIntense
	}

	// Use bits 248-251 to select color (4 bits → 16 colors)
	colorIndex := 0
	for i := 0; i < 4; i++ {
		if identicon.getBit(248 + i) {
			colorIndex |= 1 << i
		}
	}
	return palette[colorIndex%len(palette)]
}

// secondaryColor computes second color (for 2-color mode)
func (identicon *ClassicIdenticon) secondaryColor() color.Color {
	if len(identicon.source) < 32 {
		return color.RGBA{100, 100, 100, 255}
	}

	// Use different bits: 244-247 for second color
	colorIndex := 0
	for i := 0; i < 4; i++ {
		if identicon.getBit(244 + i) {
			colorIndex |= 1 << i
		}
	}

	palette := []color.RGBA{
		{0x34, 0x49, 0x5e, 0xff}, // darkBlue
		{0x95, 0xa5, 0xa5, 0xff}, // grey
		{0xd2, 0x54, 0x00, 0xff}, // brownIntense
		{0xc1, 0x39, 0x2b, 0xff}, // redIntense
		{0x29, 0x7f, 0xb8, 0xff}, // blueIntense
		{0x8d, 0x44, 0xad, 0xff}, // purpleIntense
		{0xbe, 0x12, 0x7e, 0xff}, // violetIntense
		{0xe5, 0x23, 0x83, 0xff}, // magentaIntense
		{0x27, 0xae, 0x61, 0xff}, // mintIntense
		{0x24, 0xc3, 0x33, 0xff}, // greenIntense
		{0xd9, 0xd9, 0x21, 0xff}, // yellowIntense
		{0xf3, 0x9c, 0x11, 0xff}, // yellowOrangeIntense
		{0xff, 0x55, 0x00, 0xff}, // orangeIntense
		{0x1c, 0xab, 0xbb, 0xff}, // lightBlueIntense
		{0x23, 0x23, 0x23, 0xff}, // lightBlackIntense
		{0x7e, 0x8c, 0x8d, 0xff}, // greyIntense
	}

	return palette[colorIndex%len(palette)]
}

// hslToRgb converts HSL to RGB in original style
func (identicon *ClassicIdenticon) hslToRgb(h, s, l float32) color.Color {
	hue := h / 360.0
	sat := s / 100.0
	lum := l / 100.0

	var b float32
	if lum <= 0.5 {
		b = lum * (sat + 1.0)
	} else {
		b = lum + sat - lum*sat
	}
	a := lum*2.0 - b

	red := identicon.hueToRgb(a, b, hue+1.0/3.0)
	green := identicon.hueToRgb(a, b, hue)
	blue := identicon.hueToRgb(a, b, hue-1.0/3.0)

	return color.RGBA{
		R: uint8(math.Round(float64(red * 255.0))),
		G: uint8(math.Round(float64(green * 255.0))),
		B: uint8(math.Round(float64(blue * 255.0))),
		A: 255,
	}
}

// hueToRgb helper for color conversion
func (identicon *ClassicIdenticon) hueToRgb(a, b, hue float32) float32 {
	if hue < 0 {
		hue += 1.0
	} else if hue >= 1.0 {
		hue -= 1.0
	}

	switch {
	case hue < 1.0/6.0:
		return a + (b-a)*6.0*hue
	case hue < 0.5:
		return b
	case hue < 2.0/3.0:
		return a + (b-a)*(2.0/3.0-hue)*6.0
	default:
		return a
	}
}

// drawRect draws a solid rectangle
func (identicon *ClassicIdenticon) drawRect(img *image.RGBA, x0, y0, x1, y1 int, c color.Color) {
	rect := img.Bounds()
	x0 = max(x0, rect.Min.X)
	y0 = max(y0, rect.Min.Y)
	x1 = min(x1, rect.Max.X)
	y1 = min(y1, rect.Max.Y)

	if x0 >= x1 || y0 >= y1 {
		return
	}

	r, g, b, a := c.RGBA()
	rgba := color.RGBA{
		R: uint8(r >> 8),
		G: uint8(g >> 8),
		B: uint8(b >> 8),
		A: uint8(a >> 8),
	}

	for y := y0; y < y1; y++ {
		rowStart := img.PixOffset(x0, y)
		for x := 0; x < x1-x0; x++ {
			idx := rowStart + x*4
			img.Pix[idx] = rgba.R
			img.Pix[idx+1] = rgba.G
			img.Pix[idx+2] = rgba.B
			img.Pix[idx+3] = rgba.A
		}
	}
}

// generatePixelPattern generates 5x5 symmetric pixel grid — using individual bits
// Returns two layers: primary and secondary
func (identicon *ClassicIdenticon) generatePixelPattern() ([]bool, []bool) {
	primary := make([]bool, 25)
	secondary := make([]bool, 25)

	// Use bits 0-14 for primary pattern (15 bits)
	bitIndex := 0
	for row := 0; row < 5; row++ {
		for col := 0; col < 3; col++ {
			paint := identicon.getBit(bitIndex)
			bitIndex++

			ix := row*5 + col
			mirrorIx := row*5 + (4 - col)
			primary[ix] = paint
			primary[mirrorIx] = paint
		}
	}

	// Use bits 15-29 for secondary pattern (next 15 bits)
	for row := 0; row < 5; row++ {
		for col := 0; col < 3; col++ {
			paint := identicon.getBit(bitIndex)
			bitIndex++

			ix := row*5 + col
			mirrorIx := row*5 + (4 - col)
			secondary[ix] = paint
			secondary[mirrorIx] = paint
		}
	}

	return primary, secondary
}

// Generate creates the identicon for UI display (respects theme)
func (identicon *ClassicIdenticon) Generate() image.Image {
	const (
		pixelSize  = 36
		spriteSize = 5
		margin     = (256 - pixelSize*spriteSize) / 2
	)

	primaryColor := identicon.foreground()
	secondaryColor := identicon.secondaryColor()
	img := image.NewRGBA(image.Rect(0, 0, identicon.size, identicon.size))

	// Background adapts to theme — use bits 252-254 to pick variation
	bgChoice := 0
	for i := 0; i < 3; i++ {
		if identicon.getBit(252 + i) {
			bgChoice |= 1 << i
		}
	}
	bgChoice %= 3

	lightBackgrounds := []color.RGBA{
		{255, 255, 255, 255}, // pure white
		{243, 245, 247, 255}, // light1
		{236, 240, 241, 255}, // light2
	}
	darkBackgrounds := []color.RGBA{
		{30, 30, 30, 255},    // dark gray
		{45, 62, 80, 255},     // darkBlueIntense
		{57, 57, 57, 255},     // dark2
	}

	var bg color.RGBA
	if fyne.CurrentApp().Settings().ThemeVariant() == theme.VariantDark {
		bg = darkBackgrounds[bgChoice]
	} else {
		bg = lightBackgrounds[bgChoice]
	}

	for i := 0; i < len(img.Pix); i += 4 {
		img.Pix[i] = bg.R
		img.Pix[i+1] = bg.G
		img.Pix[i+2] = bg.B
		img.Pix[i+3] = bg.A
	}

	primaryPixels, secondaryPixels := identicon.generatePixelPattern()

	// Draw secondary pixels first (background layer)
	for row := 0; row < spriteSize; row++ {
		for col := 0; col < spriteSize; col++ {
			if secondaryPixels[row*spriteSize+col] {
				x := col*pixelSize + margin
				y := row*pixelSize + margin
				identicon.drawRect(img, x, y, x+pixelSize, y+pixelSize, secondaryColor)
			}
		}
	}

	// Draw primary pixels on top (foreground layer)
	for row := 0; row < spriteSize; row++ {
		for col := 0; col < spriteSize; col++ {
			if primaryPixels[row*spriteSize+col] {
				x := col*pixelSize + margin
				y := row*pixelSize + margin
				identicon.drawRect(img, x, y, x+pixelSize, y+pixelSize, primaryColor)
			}
		}
	}

	return img
}

// GenerateForExport generates identicon with fixed background for saving
func (identicon *ClassicIdenticon) GenerateForExport(transparent bool) image.Image {
	const (
		pixelSize  = 36
		spriteSize = 5
		margin     = (256 - pixelSize*spriteSize) / 2
	)

	primaryColor := identicon.foreground()
	secondaryColor := identicon.secondaryColor()
	img := image.NewRGBA(image.Rect(0, 0, identicon.size, identicon.size))

	// Set export background
	var bg color.RGBA
	if transparent {
		bg = color.RGBA{0, 0, 0, 0} // fully transparent
	} else {
		// Use bits 252-254 for background choice
		bgChoice := 0
		for i := 0; i < 3; i++ {
			if identicon.getBit(252 + i) {
				bgChoice |= 1 << i
			}
		}
		bgChoice %= 3

		lightBackgrounds := []color.RGBA{
			{255, 255, 255, 255},
			{243, 245, 247, 255},
			{236, 240, 241, 255},
		}
		bg = lightBackgrounds[bgChoice]
	}

	for i := 0; i < len(img.Pix); i += 4 {
		img.Pix[i] = bg.R
		img.Pix[i+1] = bg.G
		img.Pix[i+2] = bg.B
		img.Pix[i+3] = bg.A
	}

	primaryPixels, secondaryPixels := identicon.generatePixelPattern()

	// Draw secondary pixels first
	for row := 0; row < spriteSize; row++ {
		for col := 0; col < spriteSize; col++ {
			if secondaryPixels[row*spriteSize+col] {
				x := col*pixelSize + margin
				y := row*pixelSize + margin
				identicon.drawRect(img, x, y, x+pixelSize, y+pixelSize, secondaryColor)
			}
		}
	}

	// Draw primary pixels on top
	for row := 0; row < spriteSize; row++ {
		for col := 0; col < spriteSize; col++ {
			if primaryPixels[row*spriteSize+col] {
				x := col*pixelSize + margin
				y := row*pixelSize + margin
				identicon.drawRect(img, x, y, x+pixelSize, y+pixelSize, primaryColor)
			}
		}
	}

	return img
}

// Helper functions
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
