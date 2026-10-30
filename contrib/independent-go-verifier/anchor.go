package verifier

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type verifiedAnchor struct {
	Origin, Class string
	At            time.Time
}
type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}
type cmsAttribute struct {
	Type   asn1.ObjectIdentifier
	Values []asn1.RawValue `asn1:"set"`
}

var oidSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
var oidTSTInfo = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
var oidContentType = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
var oidMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
var oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}

func derItems(raw []byte) ([]asn1.RawValue, error) {
	var values []asn1.RawValue
	for len(raw) > 0 {
		var v asn1.RawValue
		rest, err := asn1.Unmarshal(raw, &v)
		if err != nil {
			return nil, err
		}
		if len(rest) >= len(raw) {
			return nil, fmt.Errorf("invalid DER element")
		}
		values = append(values, v)
		raw = rest
	}
	return values, nil
}
func derOne(raw []byte, tag byte) (asn1.RawValue, error) {
	v, err := derItems(raw)
	if err != nil || len(v) != 1 || len(v[0].FullBytes) == 0 || v[0].FullBytes[0] != tag {
		return asn1.RawValue{}, fmt.Errorf("invalid DER wrapper %x", tag)
	}
	return v[0], nil
}
func derOID(raw []byte) (asn1.ObjectIdentifier, error) {
	var id asn1.ObjectIdentifier
	rest, err := asn1.Unmarshal(raw, &id)
	if err != nil || len(rest) != 0 {
		return nil, fmt.Errorf("invalid DER OID")
	}
	return id, nil
}
func digestForOID(id asn1.ObjectIdentifier) (crypto.Hash, error) {
	switch id.String() {
	case "2.16.840.1.101.3.4.2.1":
		return crypto.SHA256, nil
	case "2.16.840.1.101.3.4.2.2":
		return crypto.SHA384, nil
	case "2.16.840.1.101.3.4.2.3":
		return crypto.SHA512, nil
	}
	return 0, fmt.Errorf("unsupported digest algorithm")
}
func digestBytes(h crypto.Hash, data []byte) []byte {
	switch h {
	case crypto.SHA256:
		s := sha256.Sum256(data)
		return s[:]
	case crypto.SHA384:
		s := sha512.Sum384(data)
		return s[:]
	case crypto.SHA512:
		s := sha512.Sum512(data)
		return s[:]
	}
	return nil
}
func validAt(entry map[string]any, at time.Time) bool {
	span, ok := entry["validFor"].(map[string]any)
	if !ok {
		return false
	}
	start, ok := span["start"].(string)
	if !ok {
		return false
	}
	lo, err := time.Parse(time.RFC3339Nano, start)
	if err != nil || at.Before(lo) {
		return false
	}
	if end, exists := span["end"]; exists {
		end, ok := end.(string)
		if !ok {
			return false
		}
		hi, err := time.Parse(time.RFC3339Nano, end)
		if err != nil || at.After(hi) {
			return false
		}
	}
	return true
}

// verifyTimestamp authenticates CMS signed attributes and their TSTInfo imprint
// using only TSA certificates pinned outside the bundle. Token-carried
// certificates never establish trust.
func verifyTimestamp(tsr, data []byte, root map[string]any) (time.Time, error) {
	bad := func() (time.Time, error) { return time.Time{}, fmt.Errorf("invalid RFC3161 timestamp") }
	if len(tsr) > 64<<10 {
		return bad()
	}
	outer, err := derOne(tsr, 0x30)
	if err != nil {
		return bad()
	}
	response, err := derItems(outer.Bytes)
	if err != nil || len(response) != 2 {
		return bad()
	}
	status, err := derItems(response[0].Bytes)
	if err != nil || len(status) < 1 {
		return bad()
	}
	var code int
	if rest, e := asn1.Unmarshal(status[0].FullBytes, &code); e != nil || len(rest) != 0 || (code != 0 && code != 1) {
		return bad()
	}
	ci, err := derItems(response[1].Bytes)
	if err != nil || len(ci) != 2 || ci[1].FullBytes[0] != 0xa0 {
		return bad()
	}
	id, err := derOID(ci[0].FullBytes)
	if err != nil || !id.Equal(oidSignedData) {
		return bad()
	}
	sdRaw, err := derOne(ci[1].Bytes, 0x30)
	if err != nil {
		return bad()
	}
	sd, err := derItems(sdRaw.Bytes)
	if err != nil || len(sd) < 4 {
		return bad()
	}
	encap, err := derItems(sd[2].Bytes)
	if err != nil || len(encap) != 2 || encap[1].FullBytes[0] != 0xa0 {
		return bad()
	}
	id, err = derOID(encap[0].FullBytes)
	if err != nil || !id.Equal(oidTSTInfo) {
		return bad()
	}
	tst, err := derOne(encap[1].Bytes, 4)
	if err != nil {
		return bad()
	}
	if sd[len(sd)-1].FullBytes[0] != 0x31 {
		return bad()
	}
	signers, err := derItems(sd[len(sd)-1].Bytes)
	if err != nil || len(signers) != 1 {
		return bad()
	}
	si, err := derItems(signers[0].Bytes)
	if err != nil || len(si) < 6 || si[3].FullBytes[0] != 0xa0 || si[5].FullBytes[0] != 4 {
		return bad()
	}
	var digestAlg algorithmIdentifier
	if rest, e := asn1.Unmarshal(si[2].FullBytes, &digestAlg); e != nil || len(rest) != 0 {
		return bad()
	}
	digest, err := digestForOID(digestAlg.Algorithm)
	if err != nil {
		return bad()
	}
	attrsRaw, err := derItems(si[3].Bytes)
	if err != nil {
		return bad()
	}
	attrs := map[string]asn1.RawValue{}
	for _, raw := range attrsRaw {
		var a cmsAttribute
		rest, e := asn1.Unmarshal(raw.FullBytes, &a)
		if e != nil || len(rest) != 0 || len(a.Values) != 1 {
			return bad()
		}
		if _, ok := attrs[a.Type.String()]; ok {
			return bad()
		}
		attrs[a.Type.String()] = a.Values[0]
	}
	ct, ok := attrs[oidContentType.String()]
	if !ok {
		return bad()
	}
	id, err = derOID(ct.FullBytes)
	if err != nil || !id.Equal(oidTSTInfo) {
		return bad()
	}
	md, ok := attrs[oidMessageDigest.String()]
	if !ok || md.FullBytes[0] != 4 || !bytes.Equal(md.Bytes, digestBytes(digest, tst.Bytes)) {
		return bad()
	}
	var signatureAlg algorithmIdentifier
	if rest, e := asn1.Unmarshal(si[4].FullBytes, &signatureAlg); e != nil || len(rest) != 0 {
		return bad()
	}
	var signatureHash crypto.Hash
	var kind string
	switch signatureAlg.Algorithm.String() {
	case "1.2.840.10045.4.3.2":
		kind, signatureHash = "ecdsa", crypto.SHA256
	case "1.2.840.10045.4.3.3":
		kind, signatureHash = "ecdsa", crypto.SHA384
	case "1.2.840.10045.4.3.4":
		kind, signatureHash = "ecdsa", crypto.SHA512
	case "1.2.840.113549.1.1.11":
		kind, signatureHash = "rsa", crypto.SHA256
	case "1.2.840.113549.1.1.12":
		kind, signatureHash = "rsa", crypto.SHA384
	case "1.2.840.113549.1.1.13":
		kind, signatureHash = "rsa", crypto.SHA512
	default:
		return bad()
	}
	infoRaw, err := derOne(tst.Bytes, 0x30)
	if err != nil {
		return bad()
	}
	info, err := derItems(infoRaw.Bytes)
	if err != nil || len(info) < 5 {
		return bad()
	}
	imprint, err := derItems(info[2].Bytes)
	if err != nil || len(imprint) != 2 {
		return bad()
	}
	var imprintAlg algorithmIdentifier
	if rest, e := asn1.Unmarshal(imprint[0].FullBytes, &imprintAlg); e != nil || len(rest) != 0 || !imprintAlg.Algorithm.Equal(oidSHA256) || imprint[1].FullBytes[0] != 4 || !bytes.Equal(imprint[1].Bytes, digestBytes(crypto.SHA256, data)) {
		return bad()
	}
	if info[4].FullBytes[0] != 0x18 {
		return bad()
	}
	var at time.Time
	if rest, e := asn1.Unmarshal(info[4].FullBytes, &at); e != nil || len(rest) != 0 {
		return bad()
	}
	at = at.UTC()
	signed := append([]byte(nil), si[3].FullBytes...)
	signed[0] = 0x31
	hashed := digestBytes(signatureHash, signed)
	authorities, _ := root["timestampAuthorities"].([]any)
	for _, value := range authorities {
		ta, ok := value.(map[string]any)
		if !ok || !validAt(ta, at) {
			continue
		}
		chain, ok := ta["certChain"].(map[string]any)
		if !ok {
			continue
		}
		certs, ok := chain["certificates"].([]any)
		if !ok || len(certs) == 0 {
			continue
		}
		certSpec, ok := certs[0].(map[string]any)
		if !ok {
			continue
		}
		encoded, ok := certSpec["rawBytes"].(string)
		if !ok {
			continue
		}
		der, err := b64(encoded)
		if err != nil {
			continue
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil || at.Before(cert.NotBefore) || at.After(cert.NotAfter) {
			continue
		}
		switch key := cert.PublicKey.(type) {
		case *ecdsa.PublicKey:
			if kind == "ecdsa" && ecdsa.VerifyASN1(key, hashed, si[5].Bytes) {
				return at, nil
			}
		case *rsa.PublicKey:
			if kind == "rsa" && rsa.VerifyPKCS1v15(key, signatureHash, hashed, si[5].Bytes) == nil {
				return at, nil
			}
		}
	}
	return time.Time{}, fmt.Errorf("timestamp is not signed by a pinned TSA valid at its time")
}

func verifyAnchorSignature(spki, sig, data []byte, p256 bool) bool {
	key, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return false
	}
	switch key := key.(type) {
	case *ecdsa.PublicKey:
		if p256 && key.Curve != elliptic.P256() {
			return false
		}
		digest := sha256.Sum256(data)
		return ecdsa.VerifyASN1(key, digest[:], sig)
	case ed25519.PublicKey:
		return !p256 && validEd25519PublicKey(key) && ed25519.Verify(key, data, sig)
	}
	return false
}

func verifyAnchor(files map[string][]byte, trustBytes []byte, log VKey, cp Checkpoint, note []byte) ([]verifiedAnchor, error) {
	v, err := ParseStrict(trustBytes)
	if err != nil {
		return nil, err
	}
	trust, err := object(v)
	if err != nil {
		return nil, err
	}
	pin, ok := trust["rekor"].(map[string]any)
	if !ok || len(pin) == 0 {
		return nil, nil
	}
	raw, exists := files[fmt.Sprintf("rekor/%d.json", cp.Size)]
	if !exists {
		return nil, nil
	}
	fail := func() ([]verifiedAnchor, error) { return nil, fmt.Errorf("invalid Rekor anchor") }
	root, ok := pin["trusted_root"].(map[string]any)
	if !ok {
		return fail()
	}
	publishing, ok := pin["publishing_key"].(string)
	if !ok {
		return fail()
	}
	publishingSPKI, err := b64(publishing)
	if err != nil {
		return fail()
	}
	sections := bytes.SplitN(note, []byte("\n\n"), 2)
	if len(sections) != 2 {
		return fail()
	}
	var data []byte
	for _, line := range strings.Split(string(sections[1]), "\n") {
		parts := strings.Split(line, " ")
		if len(parts) != 3 || parts[0] != "—" || parts[1] != log.Name {
			continue
		}
		sig, e := b64(parts[2])
		if e == nil && len(sig) >= 4 && bytes.Equal(sig[:4], log.ID[:]) {
			data = append(append(append([]byte(nil), sections[0]...), []byte("\n\n")...), []byte(line+"\n")...)
			break
		}
	}
	if data == nil {
		return fail()
	}
	at, err := verifyTimestamp(files[fmt.Sprintf("tsa/%d.tsr", cp.Size)], data, root)
	if err != nil {
		return nil, err
	}
	parsed, err := ParseStrict(raw)
	if err != nil {
		return nil, err
	}
	tle, err := object(parsed)
	if err != nil {
		return fail()
	}
	encoded, ok := tle["canonicalizedBody"].(string)
	if !ok {
		return fail()
	}
	body, err := b64(encoded)
	if err != nil {
		return fail()
	}
	parsed, err = ParseStrict(body)
	if err != nil {
		return fail()
	}
	entry, err := object(parsed)
	if err != nil || entry["apiVersion"] != "0.0.2" || entry["kind"] != "hashedrekord" {
		return fail()
	}
	specs, ok := entry["spec"].(map[string]any)
	if !ok {
		return fail()
	}
	spec, ok := specs["hashedRekordV002"].(map[string]any)
	if !ok {
		return fail()
	}
	imprint, ok := spec["data"].(map[string]any)
	if !ok || len(imprint) != 2 || imprint["algorithm"] != "SHA2_256" {
		return fail()
	}
	digestText, ok := imprint["digest"].(string)
	if !ok {
		return fail()
	}
	digest, err := b64(digestText)
	if err != nil || !bytes.Equal(digest, digestBytes(crypto.SHA256, data)) {
		return fail()
	}
	signature, ok := spec["signature"].(map[string]any)
	if !ok {
		return fail()
	}
	verifier, ok := signature["verifier"].(map[string]any)
	if !ok || verifier["keyDetails"] != "PKIX_ECDSA_P256_SHA_256" {
		return fail()
	}
	public, ok := verifier["publicKey"].(map[string]any)
	if !ok || public["rawBytes"] != publishing {
		return fail()
	}
	sigText, ok := signature["content"].(string)
	if !ok {
		return fail()
	}
	sig, err := b64(sigText)
	if err != nil || !verifyAnchorSignature(publishingSPKI, sig, data, true) {
		return fail()
	}
	logID, ok := tle["logId"].(map[string]any)
	if !ok {
		return fail()
	}
	idText, ok := logID["keyId"].(string)
	if !ok {
		return fail()
	}
	logIDBytes, err := b64(idText)
	if err != nil || len(logIDBytes) < 4 {
		return fail()
	}
	var shard map[string]any
	tlogs, _ := root["tlogs"].([]any)
	for _, t := range tlogs {
		m, ok := t.(map[string]any)
		if !ok {
			continue
		}
		id, ok := m["logId"].(map[string]any)
		if ok && id["keyId"] == idText {
			shard = m
			break
		}
	}
	if shard == nil {
		return fail()
	}
	shardKey, ok := shard["publicKey"].(map[string]any)
	if !ok || !validAt(shardKey, at) {
		return fail()
	}
	spkiText, ok := shardKey["rawBytes"].(string)
	if !ok {
		return fail()
	}
	spki, err := b64(spkiText)
	if err != nil {
		return fail()
	}
	ip, ok := tle["inclusionProof"].(map[string]any)
	if !ok {
		return fail()
	}
	size, err := protoUint(ip["treeSize"])
	if err != nil {
		return fail()
	}
	index, err := protoUint(ip["logIndex"])
	if err != nil {
		return fail()
	}
	rootText, ok := ip["rootHash"].(string)
	if !ok {
		return fail()
	}
	rootBytes, err := b64(rootText)
	if err != nil || len(rootBytes) != 32 {
		return fail()
	}
	var merkleRoot [32]byte
	copy(merkleRoot[:], rootBytes)
	path, err := proofPath(ip["hashes"])
	if err != nil {
		return fail()
	}
	if err := verifyLeafProof(body, index, size, path, merkleRoot); err != nil {
		return nil, err
	}
	checkpoint, ok := ip["checkpoint"].(map[string]any)
	if !ok {
		return fail()
	}
	envelope, ok := checkpoint["envelope"].(string)
	if !ok {
		return fail()
	}
	parts := strings.SplitN(envelope, "\n\n", 2)
	if len(parts) != 2 {
		return fail()
	}
	head := strings.Split(parts[0], "\n")
	if len(head) != 3 {
		return fail()
	}
	n, err := strconv.ParseUint(head[1], 10, 64)
	if err != nil || n != size || head[2] != rootText {
		return fail()
	}
	verified := false
	for _, line := range strings.Split(parts[1], "\n") {
		p := strings.Split(line, " ")
		if len(p) != 3 || p[0] != "—" || p[1] != head[0] {
			continue
		}
		signature, err := b64(p[2])
		if err == nil && len(signature) > 4 && bytes.Equal(signature[:4], logIDBytes[:4]) && verifyAnchorSignature(spki, signature[4:], []byte(parts[0]+"\n"), false) {
			verified = true
		}
	}
	if !verified {
		return fail()
	}
	class, ok := pin["class"].(string)
	if !ok {
		return fail()
	}
	return []verifiedAnchor{{head[0], class, at}}, nil
}
func protoUint(v any) (uint64, error) {
	if s, ok := v.(string); ok {
		if s == "" || strings.Trim(s, "0123456789") != "" {
			return 0, fmt.Errorf("bad unsigned integer")
		}
		return strconv.ParseUint(s, 10, 64)
	}
	return fieldInt(map[string]any{"n": v}, "n")
}
