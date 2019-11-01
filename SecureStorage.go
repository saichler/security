package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	. "github.com/saichler/utils/golang"
	"io"
	"io/ioutil"
	mathrand "math/rand"
	"os"
	"strconv"
	"time"
)

const (
	a = "ea3a"
	b = "4332-"
	c = "4f34"
	d = "-4e72-b"
	e = "3bd-c"
	f = "04489cf"
)

var l = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
var g = []rune(a + b + c + d + e + f)

type pair struct {
	aside int
	bside int
}

type storage struct {
	filename string
	key      []byte
	data     map[string][]byte
	pairs    []*pair
}

func (s *storage) exist(x int) bool {
	for i := 0; i < len(s.pairs); i++ {
		if s.pairs[i].aside == x || s.pairs[i].bside == x {
			return true
		}
	}
	return false
}

func (s *storage) addpair() {
	mathrand.Seed(time.Now().UnixNano())
	pr := pair{}
	rnd := mathrand.Intn(32)
	for ; s.exist(rnd); {
		rnd = mathrand.Intn(32)
	}
	pr.aside = rnd
	for ; s.exist(rnd) || rnd == pr.aside; {
		rnd = mathrand.Intn(32)
	}
	pr.bside = rnd
	s.pairs = append(s.pairs, &pr)
}

func GenerateAES256Key() string {
	mathrand.Seed(time.Now().UnixNano())
	key := make([]rune, 32)
	for i := range key {
		key[i] = l[mathrand.Intn(len(l))]
	}
	return string(key)
}

func (s *storage) validate(data []byte) {
	for i := 0; i < len(s.pairs); i++ {
		aside := data[s.pairs[i].aside]
		bside := data[s.pairs[i].bside]
		data[s.pairs[i].aside] = bside
		data[s.pairs[i].bside] = aside
	}
}

func InitSecureStore(filename string) *storage {
	s := storage{}
	s.filename = filename
	s.data = make(map[string][]byte)
	s.load()
	return &s
}

func (s *storage) Put(key, value string) error {
	k, err := s.convert()
	if err != nil {
		return err
	}
	evalue, err := Encode([]byte(value), k)
	if err != nil {
		return err
	}
	s.data[key] = evalue
	return s.store()
}

func (s *storage) convert() (string, error) {
	kb := make([]byte, 0)
	kb = append(kb, s.key...)
	s.validate(kb)
	dd, err := Decode(kb, string(g))
	if err != nil {
		return "", err
	}
	result := string(dd)
	return result, nil
}

func (s *storage) Get(key string) (string, error) {
	k, err := s.convert()
	if err != nil {
		return "", err
	}
	evalue := s.data[key]
	d, err := Decode([]byte(evalue), k)
	if err != nil {
		return "", err
	}
	return string(d), nil
}

func (s *storage) store() error {
	k, e := s.convert()
	if e != nil {
		return e
	}
	ba := NewByteSlice()
	for i := 0; i < len(s.pairs); i++ {
		ba.AddInt(s.pairs[i].aside)
		ba.AddInt(s.pairs[i].bside)
	}
	ba.AddByteSlice(s.key)
	for key, value := range s.data {
		kd, e := Encode([]byte(key), k)
		if e != nil {
			return e
		}
		ba.Put(kd, value)
	}
	err := ioutil.WriteFile(s.filename, ba.Data(), 0777)
	if err != nil {
		Error("Failed to store data to file "+s.filename+"! ", err)
		return err
	}
	return nil
}

func (s *storage) create() error {
	newkey := GenerateAES256Key()
	for i := 0; i < 4; i++ {
		s.addpair()
	}
	keydata, err := Encode([]byte(newkey), string(g))
	if err != nil {
		return err
	}
	s.validate(keydata)
	s.key = keydata
	return s.store()
}

func (s *storage) load() error {
	_, err := os.Stat(s.filename)
	if err != nil {
		Info("storage does not exist, creating it!")
		return s.create()
	}
	buff, err := ioutil.ReadFile(s.filename)
	if err != nil {
		Error("Failed to read storage file! ", err)
		return err
	}

	ba := NewByteSliceWithData(buff, 0)

	for i := 0; i < 4; i++ {
		aside := ba.GetInt()
		bside := ba.GetInt()
		p := pair{}
		p.aside = aside
		p.bside = bside
		s.pairs = append(s.pairs, &p)
	}
	s.key = ba.GetByteSlice()
	k, err := s.convert()
	if err != nil {
		return err
	}
	for ; !ba.IsEOF(); {
		key, value := ba.Get()
		kd, err := Decode(key, k)
		if err != nil {
			return err
		}
		ks := string(kd)
		s.data[ks] = value
	}
	return nil
}

func Encode(data []byte, key string) ([]byte, error) {
	k := []byte(key)
	block, err := aes.NewCipher(k)
	if err != nil {
		Info("Failed to load encryption cipher! ", err)
		return data, err
	}

	b := base64.StdEncoding.EncodeToString(data)
	cipherdata := make([]byte, aes.BlockSize+len(b))

	iv := cipherdata[:aes.BlockSize]
	_, err = io.ReadFull(rand.Reader, iv)
	if err != nil {
		Error("Failed to encrypt data! ", err)
		return data, err
	}

	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(cipherdata[aes.BlockSize:], []byte(b))
	return cipherdata, nil
}

func Decode(encData []byte, key string) ([]byte, error) {
	if len(encData) < aes.BlockSize {
		err := errors.New("Encrypted data does not have an IV spec!")
		Error("Encrypted data does not have an IV spec!")
		return encData, err
	}
	k := []byte(key)
	block, err := aes.NewCipher(k)
	if err != nil {
		Error("Failed to load encryption cipher! ", err)
		return encData, err
	}
	iv := encData[:aes.BlockSize]
	encData = encData[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(encData, encData)
	data, err := base64.StdEncoding.DecodeString(string(encData))
	if err != nil {
		Error("Failed to decrypt data! ", err)
		return encData, err
	}
	return data, nil
}

func Hash256(data []byte) string {
	sha256Hash := sha256.New()
	sha256Hash.Write(data)
	hash := sha256Hash.Sum(nil)
	return base64.URLEncoding.EncodeToString(hash)
}

func FileHash256(filename string) (string, error) {
	stat, err := os.Stat(filename)
	if os.IsNotExist(err) {
		Error("File " + filename + " does not exist.")
		return "", err
	}

	file, err := os.Open(filename)
	if err != nil {
		Error("Failed to open the file "+filename, err)
		return "", err
	}

	sha256Hash := sha256.New()
	var fileHash []byte

	var parts int64
	var block int64
	block = 1024 * 1024
	parts = stat.Size() / block
	if stat.Size()%block != 0 {
		parts++
	}

	var i int64
	for i = 0; i < parts; i++ {
		toRead := block
		if stat.Size() < i*block+block {
			toRead = stat.Size() - i*block
		}
		data := make([]byte, toRead)
		_, err = file.Read(data)
		if err != nil {
			Error("Failed to read part "+strconv.Itoa(int(i))+" from file:", err)
			return "", err
		}
		sha256Hash.Write(data)
		fileHash = sha256Hash.Sum(nil)
	}
	err = file.Close()
	if err != nil {
		Error("Failed to close the file " + filename)
		return "", err
	}
	return base64.URLEncoding.EncodeToString(fileHash), nil
}
