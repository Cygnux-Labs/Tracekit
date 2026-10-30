// Package verifier implements independently specified Tracekit format-v2 primitives.
// It intentionally does not depend on Tracekit's Python or TypeScript implementations.
package verifier

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

const ZeroHash = "sha256:" + "0000000000000000000000000000000000000000000000000000000000000000"

// ParseStrict rejects ambiguous input before anything can be hashed or signed.
// The depth limit counts arrays and objects, not scalar values.
func ParseStrict(input []byte) (any, error) {
	if !utf8.Valid(input) {
		return nil, errors.New("invalid_utf8")
	}
	if hasNonFiniteToken(input) {
		return nil, errors.New("non_finite")
	}
	if err := checkUTF16Escapes(input); err != nil {
		return nil, err
	}
	d := json.NewDecoder(bytes.NewReader(input))
	d.UseNumber()
	v, err := readValue(d, 0)
	if err != nil {
		return nil, err
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, errors.New("syntax: trailing data")
	}
	return v, nil
}

func readValue(d *json.Decoder, depth int) (any, error) {
	t, err := d.Token()
	if err != nil {
		return nil, fmt.Errorf("syntax: %w", err)
	}
	switch x := t.(type) {
	case json.Delim:
		if x != '{' && x != '[' {
			return nil, errors.New("syntax: unexpected closing delimiter")
		}
		if depth >= 128 {
			return nil, errors.New("depth")
		}
		if x == '[' {
			a := []any{}
			for d.More() {
				child, e := readValue(d, depth+1)
				if e != nil {
					return nil, e
				}
				a = append(a, child)
			}
			end, e := d.Token()
			if e != nil || end != json.Delim(']') {
				return nil, errors.New("syntax: bad array")
			}
			return a, nil
		}
		m := make(map[string]any)
		for d.More() {
			k, e := d.Token()
			if e != nil {
				return nil, fmt.Errorf("syntax: %w", e)
			}
			key, ok := k.(string)
			if !ok {
				return nil, errors.New("syntax: object key is not a string")
			}
			if _, exists := m[key]; exists {
				return nil, errors.New("duplicate_key")
			}
			child, e := readValue(d, depth+1)
			if e != nil {
				return nil, e
			}
			m[key] = child
		}
		end, e := d.Token()
		if e != nil || end != json.Delim('}') {
			return nil, errors.New("syntax: bad object")
		}
		return m, nil
	case json.Number:
		s := string(x)
		if !strings.ContainsAny(s, ".eE") {
			digit := strings.TrimPrefix(s, "-")
			if len(digit) > 16 {
				return nil, errors.New("int_range")
			}
			bi := new(big.Int)
			if _, ok := bi.SetString(s, 10); !ok {
				return nil, errors.New("syntax")
			}
			limit := big.NewInt(9007199254740991)
			if new(big.Int).Abs(bi).Cmp(limit) > 0 {
				return nil, errors.New("int_range")
			}
		}
		f, e := strconv.ParseFloat(s, 64)
		if e != nil || math.IsInf(f, 0) || math.IsNaN(f) {
			return nil, errors.New("non_finite")
		}
		return x, nil
	default:
		return t, nil
	}
}

// hasNonFiniteToken recognizes the three non-JSON number spellings used in
// Tracekit's published parser vectors. It does not interpret quoted text or
// prefixes of identifiers (for example, "NaNx" remains a syntax error).
// Parsing still happens after this scan: matching a token never makes invalid
// surrounding JSON acceptable.
func hasNonFiniteToken(input []byte) bool {
	quoted, escaped := false, false
	for i := 0; i < len(input); i++ {
		c := input[i]
		if quoted {
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == '"' {
				quoted = false
			}
			continue
		}
		if c == '"' {
			quoted = true
			continue
		}
		if i > 0 && !isJSONValuePrefix(input[i-1]) {
			continue
		}
		for _, spelling := range []string{"-Infinity", "Infinity", "NaN"} {
			if bytes.HasPrefix(input[i:], []byte(spelling)) {
				end := i + len(spelling)
				if end == len(input) || isJSONValueSuffix(input[end]) {
					return true
				}
			}
		}
	}
	return false
}

func isJSONValuePrefix(b byte) bool {
	return b == ':' || b == ',' || b == '[' || b == ' ' || b == '\t' || b == '\r' || b == '\n'
}

func isJSONValueSuffix(b byte) bool {
	return b == ',' || b == ']' || b == '}' || b == ' ' || b == '\t' || b == '\r' || b == '\n'
}

// checkUTF16Escapes scans JSON string tokens only, rejecting unpaired UTF-16
// surrogates before encoding/json can silently replace them with U+FFFD.
func checkUTF16Escapes(input []byte) error {
	for i := 0; i < len(input); i++ {
		if input[i] != '"' {
			continue
		}
		i++
		for i < len(input) && input[i] != '"' {
			if input[i] != '\\' {
				i++
				continue
			}
			i++
			if i >= len(input) {
				return errors.New("syntax")
			}
			if input[i] != 'u' {
				i++
				continue
			}
			if i+4 >= len(input) {
				return errors.New("syntax")
			}
			hi, err := strconv.ParseUint(string(input[i+1:i+5]), 16, 16)
			if err != nil {
				return errors.New("syntax")
			}
			i += 5
			if hi >= 0xDC00 && hi <= 0xDFFF {
				return errors.New("lone_surrogate")
			}
			if hi < 0xD800 || hi > 0xDBFF {
				continue
			}
			if i+5 >= len(input) || input[i] != '\\' || input[i+1] != 'u' {
				return errors.New("lone_surrogate")
			}
			low, err := strconv.ParseUint(string(input[i+2:i+6]), 16, 16)
			if err != nil || low < 0xDC00 || low > 0xDFFF {
				return errors.New("lone_surrogate")
			}
			i += 6
		}
		if i >= len(input) {
			return errors.New("syntax")
		}
	}
	return nil
}

// Canonical implements the RFC 8785 JSON canonicalization rules, including
// UTF-16 member sorting and ECMAScript-style shortest binary64 numbers.
func Canonical(value any) ([]byte, error) {
	var b bytes.Buffer
	if err := writeJCS(&b, value); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
func writeJCS(b *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if x {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case string:
		jcsString(b, x)
	case float64:
		if math.IsInf(x, 0) || math.IsNaN(x) {
			return errors.New("non_finite")
		}
		if x == 0 {
			b.WriteByte('0')
			return nil
		}
		abs := math.Abs(x)
		if abs >= 1e-6 && abs < 1e21 {
			b.WriteString(strconv.FormatFloat(x, 'f', -1, 64))
		} else {
			s := strconv.FormatFloat(x, 'e', -1, 64)
			parts := strings.Split(s, "e")
			exponent, _ := strconv.Atoi(parts[1])
			b.WriteString(parts[0])
			if exponent >= 0 {
				fmt.Fprintf(b, "e+%d", exponent)
			} else {
				fmt.Fprintf(b, "e%d", exponent)
			}
		}
	case json.Number:
		f, err := strconv.ParseFloat(string(x), 64)
		if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
			return errors.New("non_finite")
		}
		return writeJCS(b, f)
	case []any:
		b.WriteByte('[')
		for i, elem := range x {
			if i != 0 {
				b.WriteByte(',')
			}
			if err := writeJCS(b, elem); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case map[string]any:
		names := make([]string, 0, len(x))
		for key := range x {
			names = append(names, key)
		}
		slices.SortFunc(names, utf16Compare)
		b.WriteByte('{')
		for i, key := range names {
			if i != 0 {
				b.WriteByte(',')
			}
			jcsString(b, key)
			b.WriteByte(':')
			if err := writeJCS(b, x[key]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return fmt.Errorf("unsupported canonical JSON value %T", v)
	}
	return nil
}
func utf16Compare(a, b string) int {
	x, y := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	return slices.Compare(x, y)
}
func jcsString(out *bytes.Buffer, s string) {
	out.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			out.WriteString(`\"`)
		case '\\':
			out.WriteString(`\\`)
		case '\b':
			out.WriteString(`\b`)
		case '\t':
			out.WriteString(`\t`)
		case '\n':
			out.WriteString(`\n`)
		case '\f':
			out.WriteString(`\f`)
		case '\r':
			out.WriteString(`\r`)
		default:
			if r < 0x20 {
				fmt.Fprintf(out, `\u%04x`, r)
			} else {
				out.WriteRune(r)
			}
		}
	}
	out.WriteByte('"')
}

func SHA256Hex(data []byte) string {
	digest := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(digest[:])
}
func hexDigest(s string) ([]byte, error) {
	if !strings.HasPrefix(s, "sha256:") || len(s) != 71 {
		return nil, errors.New("invalid sha256 digest")
	}
	d, err := hex.DecodeString(strings.TrimPrefix(s, "sha256:"))
	if err != nil || hex.EncodeToString(d) != s[7:] {
		return nil, errors.New("invalid sha256 digest")
	}
	return d, nil
}
func b64(s string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil || base64.StdEncoding.EncodeToString(data) != s {
		return nil, errors.New("invalid canonical base64")
	}
	return data, nil
}
func fieldString(m map[string]any, name string) (string, error) {
	v, ok := m[name].(string)
	if !ok {
		return "", fmt.Errorf("%s must be a string", name)
	}
	return v, nil
}
func fieldInt(m map[string]any, name string) (uint64, error) {
	v, ok := m[name].(json.Number)
	if !ok || strings.ContainsAny(string(v), ".eE") {
		return 0, fmt.Errorf("%s must be an integer token", name)
	}
	n, err := strconv.ParseUint(string(v), 10, 64)
	if err != nil || n > 9007199254740991 {
		return 0, fmt.Errorf("%s must be a safe nonnegative integer", name)
	}
	return n, nil
}

// VerifyRecord checks the record envelope, hash, key id, and domain-separated
// Ed25519 signature against an external DER SPKI. It does not check a run chain.
func VerifyRecord(raw []byte, spki []byte) (map[string]any, error) {
	v, err := ParseStrict(raw)
	if err != nil {
		return nil, err
	}
	record, ok := v.(map[string]any)
	if !ok || len(record) != 6 {
		return nil, errors.New("record must have six fields")
	}
	for _, key := range []string{"v", "event", "hash", "alg", "kid", "sig"} {
		if _, exists := record[key]; !exists {
			return nil, fmt.Errorf("missing record field %s", key)
		}
	}
	version, err := fieldInt(record, "v")
	if err != nil || version != 2 || record["alg"] != "ed25519" {
		return nil, errors.New("unsupported record version or algorithm")
	}
	event, ok := record["event"].(map[string]any)
	if !ok {
		return nil, errors.New("event must be an object")
	}
	if _, err := fieldInt(event, "seq"); err != nil {
		return nil, err
	}
	if _, err := fieldInt(event, "run_seq"); err != nil {
		return nil, err
	}
	hash, err := fieldString(record, "hash")
	if err != nil {
		return nil, err
	}
	canonical, err := Canonical(event)
	if err != nil {
		return nil, err
	}
	if SHA256Hex(canonical) != hash {
		return nil, errors.New("record event hash mismatch")
	}
	kid, err := fieldString(record, "kid")
	if err != nil {
		return nil, err
	}
	if kid != SHA256Hex(spki) {
		return nil, errors.New("record key id mismatch")
	}
	pub, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return nil, fmt.Errorf("bad SPKI: %w", err)
	}
	key, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("SPKI is not Ed25519")
	}
	canonicalSPKI, err := x509.MarshalPKIXPublicKey(key)
	if err != nil || !bytes.Equal(canonicalSPKI, spki) {
		return nil, errors.New("noncanonical SPKI")
	}
	if !validEd25519PublicKey(key) {
		return nil, errors.New("noncanonical or small-order Ed25519 key")
	}
	message := map[string]any{"t": "tracekit.record.v2", "alg": "ed25519", "kid": kid, "hash": hash}
	for _, name := range []string{"log_id", "seq", "prev_hash", "tenant", "run_id", "run_seq", "run_prev_hash"} {
		val, exists := event[name]
		if !exists {
			return nil, fmt.Errorf("missing event position %s", name)
		}
		message[name] = val
	}
	msg, err := Canonical(message)
	if err != nil {
		return nil, err
	}
	sigStr, err := fieldString(record, "sig")
	if err != nil {
		return nil, err
	}
	sig, err := b64(sigStr)
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(key, msg, sig) {
		return nil, errors.New("invalid Ed25519 record signature")
	}
	return record, nil
}

// A compressed Edwards point has small order iff [8]P is the identity.
// The standard library verifies the cofactorless equation but does not check
// the public point's order, so reject that case explicitly.
func validEd25519PublicKey(pub ed25519.PublicKey) bool {
	if len(pub) != 32 {
		return false
	}
	p := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	encoded := append([]byte(nil), pub...)
	sign := encoded[31] >> 7
	encoded[31] &= 0x7f
	for i, j := 0, len(encoded)-1; i < j; i, j = i+1, j-1 {
		encoded[i], encoded[j] = encoded[j], encoded[i]
	}
	y := new(big.Int).SetBytes(encoded)
	if y.Cmp(p) >= 0 {
		return false
	}
	mod := func(a *big.Int) *big.Int { return new(big.Int).Mod(a, p) }
	mul := func(a, b *big.Int) *big.Int { return mod(new(big.Int).Mul(a, b)) }
	inv := func(a *big.Int) *big.Int { return new(big.Int).ModInverse(a, p) }
	d := mul(big.NewInt(-121665), inv(big.NewInt(121666)))
	y2 := mul(y, y)
	num := mod(new(big.Int).Sub(y2, big.NewInt(1)))
	den := mod(new(big.Int).Add(mul(d, y2), big.NewInt(1)))
	denInv := inv(den)
	if denInv == nil {
		return false
	}
	x2 := mul(num, denInv)
	exp := new(big.Int).Rsh(new(big.Int).Add(p, big.NewInt(3)), 3)
	x := new(big.Int).Exp(x2, exp, p)
	if mul(x, x).Cmp(x2) != 0 {
		sqrtM1 := new(big.Int).Exp(big.NewInt(2), new(big.Int).Rsh(new(big.Int).Sub(p, big.NewInt(1)), 2), p)
		x = mul(x, sqrtM1)
		if mul(x, x).Cmp(x2) != 0 {
			return false
		}
	}
	if byte(x.Bit(0)) != sign {
		x = mod(new(big.Int).Neg(x))
	}
	if x.Sign() == 0 && sign == 1 {
		return false
	}
	// Edwards point doubling: x' = (2xy)/(1+d*x²*y²),
	// y' = (y²+x²)/(1-d*x²*y²) on a=-1.
	for i := 0; i < 3; i++ {
		x2, y2 := mul(x, x), mul(y, y)
		dx2y2 := mul(d, mul(x2, y2))
		dx := inv(mod(new(big.Int).Add(big.NewInt(1), dx2y2)))
		dy := inv(mod(new(big.Int).Sub(big.NewInt(1), dx2y2)))
		if dx == nil || dy == nil {
			return false
		}
		nx := mul(mul(big.NewInt(2), mul(x, y)), dx)
		ny := mul(mod(new(big.Int).Add(x2, y2)), dy)
		x, y = nx, ny
	}
	return x.Sign() != 0 || y.Cmp(big.NewInt(1)) != 0
}

func leafHash(data []byte) [32]byte { return sha256.Sum256(append([]byte{0}, data...)) }
func nodeHash(a, b [32]byte) [32]byte {
	return sha256.Sum256(append(append([]byte{1}, a[:]...), b[:]...))
}

// VerifyInclusion implements the RFC 9162 §2.1.3.2 algorithm, which also
// handles odd-sized, non-perfect RFC 6962 Merkle trees.
func VerifyInclusion(recordHash string, index, size uint64, path []string, root [32]byte) error {
	if size == 0 || index >= size {
		return errors.New("out of range leaf")
	}
	raw, err := hexDigest(recordHash)
	if err != nil {
		return err
	}
	acc := leafHash(raw)
	fn, sn := index, size-1
	for _, entry := range path {
		sibRaw, err := b64(entry)
		if err != nil || len(sibRaw) != 32 {
			return errors.New("invalid inclusion sibling")
		}
		var sibling [32]byte
		copy(sibling[:], sibRaw)
		if sn == 0 {
			return errors.New("oversized inclusion proof")
		}
		if fn&1 == 1 || fn == sn {
			acc = nodeHash(sibling, acc)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			acc = nodeHash(acc, sibling)
		}
		fn >>= 1
		sn >>= 1
	}
	if fn != 0 || sn != 0 || acc != root {
		return errors.New("inclusion proof mismatch")
	}
	return nil
}

type VKey struct {
	Name string
	Type byte
	ID   [4]byte
	Pub  ed25519.PublicKey
}

func ParseVKey(input string) (VKey, error) {
	// Base64 may itself contain '+': locate the eight-hex-digit delimiter,
	// never split on the final '+' in the key material.
	prev, last := -1, -1
	for i := 1; i+10 <= len(input); i++ {
		if input[i] != '+' || input[i+9] != '+' {
			continue
		}
		if id, err := hex.DecodeString(input[i+1 : i+9]); err == nil && len(id) == 4 && hex.EncodeToString(id) == input[i+1:i+9] {
			prev, last = i, i+9
			break
		}
	}
	if prev < 0 {
		return VKey{}, errors.New("invalid vkey")
	}
	name := input[:prev]
	if !validNoteName(name) {
		return VKey{}, errors.New("invalid key name")
	}
	idText := input[prev+1 : last]
	idRaw, err := hex.DecodeString(idText)
	if err != nil || len(idRaw) != 4 || hex.EncodeToString(idRaw) != idText {
		return VKey{}, errors.New("invalid vkey id")
	}
	raw, err := b64(input[last+1:])
	if err != nil || len(raw) != 33 || (raw[0] != 1 && raw[0] != 4) {
		return VKey{}, errors.New("unsupported vkey type")
	}
	sum := sha256.Sum256(append(append([]byte(name+"\n"), raw[0]), raw[1:]...))
	if !bytes.Equal(sum[:4], idRaw) {
		return VKey{}, errors.New("incorrect vkey id")
	}
	if !validEd25519PublicKey(raw[1:]) {
		return VKey{}, errors.New("invalid vkey public key")
	}
	var id [4]byte
	copy(id[:], idRaw)
	return VKey{name, raw[0], id, raw[1:]}, nil
}

type Checkpoint struct {
	Origin       string
	Size         uint64
	Root         [32]byte
	Witnesses    int
	Cosignatures []Cosignature
}

type Cosignature struct {
	Key  VKey
	Time uint64
}

func validNoteName(name string) bool {
	if name == "" || len(name) > 255 || strings.Contains(name, "+") || !utf8.ValidString(name) {
		return false
	}
	for _, r := range name {
		if r < 0x20 || unicode.IsSpace(r) {
			return false
		}
	}
	return true
}

// VerifyCheckpoint checks C2SP signed-note and tlog-cosignature/v1 signatures.
// Pins must come from the auditor's own trust config, never from the bundle.
func VerifyCheckpoint(note []byte, log VKey, witnesses []VKey, quorum int) (Checkpoint, error) {
	if len(note) > 1<<20 || quorum < 0 {
		return Checkpoint{}, errors.New("invalid checkpoint size/quorum")
	}
	if !utf8.Valid(note) {
		return Checkpoint{}, errors.New("checkpoint is not UTF-8")
	}
	for _, r := range string(note) {
		if r < 0x20 && r != '\n' {
			return Checkpoint{}, errors.New("control character in checkpoint")
		}
	}
	sections := bytes.SplitN(note, []byte("\n\n"), 2)
	if len(sections) != 2 {
		return Checkpoint{}, errors.New("invalid note layout")
	}
	text := append(append([]byte(nil), sections[0]...), '\n')
	if len(text) == 0 || text[len(text)-1] != '\n' {
		return Checkpoint{}, errors.New("invalid checkpoint text")
	}
	head := strings.Split(string(sections[0]), "\n")
	if len(head) != 3 || head[0] == "" || head[1] == "" || (len(head[1]) > 1 && head[1][0] == '0') {
		return Checkpoint{}, errors.New("invalid checkpoint header")
	}
	if !validNoteName(head[0]) {
		return Checkpoint{}, errors.New("invalid checkpoint origin")
	}
	if strings.Trim(head[1], "0123456789") != "" {
		return Checkpoint{}, errors.New("invalid tree size")
	}
	size, err := strconv.ParseUint(head[1], 10, 64)
	if err != nil {
		return Checkpoint{}, err
	}
	rawRoot, err := b64(head[2])
	if err != nil || len(rawRoot) != 32 {
		return Checkpoint{}, errors.New("invalid checkpoint root")
	}
	if log.Name != head[0] || log.Type != 1 {
		return Checkpoint{}, errors.New("log pin does not match origin")
	}
	cp := Checkpoint{Origin: head[0], Size: size}
	copy(cp.Root[:], rawRoot)
	pins := make(map[string]VKey)
	pins[log.Name+"/"+hex.EncodeToString(log.ID[:])+"/1"] = log
	for _, k := range witnesses {
		if k.Type != 4 {
			return Checkpoint{}, errors.New("invalid witness type")
		}
		id := k.Name + "/" + hex.EncodeToString(k.ID[:]) + "/4"
		if _, ok := pins[id]; ok {
			return Checkpoint{}, errors.New("duplicate trust pin")
		}
		pins[id] = k
	}
	seen := make(map[string]bool)
	seenLines := make(map[string]bool)
	logSigned := false
	rawLines := strings.Split(string(sections[1]), "\n")
	if len(rawLines) < 2 || rawLines[len(rawLines)-1] != "" || len(rawLines)-1 > 64 {
		return Checkpoint{}, errors.New("invalid signature lines")
	}
	for _, line := range rawLines[:len(rawLines)-1] {
		if !strings.HasPrefix(line, "— ") {
			return Checkpoint{}, errors.New("invalid note signature prefix")
		}
		pieces := strings.Split(line[4:], " ")
		if len(pieces) != 2 || !validNoteName(pieces[0]) || pieces[1] == "" {
			return Checkpoint{}, errors.New("invalid note signature syntax")
		}
		signature, err := b64(pieces[1])
		if err != nil || len(signature) < 5 {
			return Checkpoint{}, errors.New("invalid checkpoint signature encoding")
		}
		lineID := pieces[0] + "/" + hex.EncodeToString(signature[:4])
		if seenLines[lineID] {
			return Checkpoint{}, errors.New("duplicate checkpoint signature")
		}
		seenLines[lineID] = true
		for _, key := range pins {
			if key.Name != pieces[0] || !bytes.Equal(key.ID[:], signature[:4]) {
				continue
			}
			id := key.Name + "/" + hex.EncodeToString(key.ID[:]) + "/" + strconv.Itoa(int(key.Type))
			if seen[id] {
				return Checkpoint{}, errors.New("duplicate pinned signature")
			}
			seen[id] = true
			var msg []byte
			var sig []byte
			switch key.Type {
			case 1:
				msg = text
				sig = signature[4:]
			case 4:
				if len(signature) != 4+8+64 {
					return Checkpoint{}, errors.New("invalid witness signature size")
				}
				t := binary.BigEndian.Uint64(signature[4:12])
				msg = []byte(fmt.Sprintf("cosignature/v1\ntime %d\n", t))
				msg = append(msg, text...)
				sig = signature[12:]
			}
			if len(sig) != 64 || !ed25519.Verify(key.Pub, msg, sig) {
				return Checkpoint{}, errors.New("invalid pinned checkpoint signature")
			}
			if key.Type == 1 {
				logSigned = true
			} else {
				cp.Witnesses++
				cp.Cosignatures = append(cp.Cosignatures, Cosignature{key, binary.BigEndian.Uint64(signature[4:12])})
			}
		}
	}
	if !logSigned {
		return Checkpoint{}, errors.New("missing pinned log signature")
	}
	if cp.Witnesses < quorum {
		return Checkpoint{}, errors.New("witness quorum not met")
	}
	return cp, nil
}
