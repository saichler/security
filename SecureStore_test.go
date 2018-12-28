package security

import "testing"
import (
	"os"
)

const (
	FILENAME="/tmp/test.bin"
)

func initializeStorage(){
	_,err := os.Stat(FILENAME)
	if err!=nil {
		os.Remove(FILENAME)
	}
	st := InitSecureStore(FILENAME)
	st.Put("/path1/key1","hello")
	st.Put("/path1/key2", "world")
	st.Put("/path2/key1", "have")
	st.Put("/path2/key2","a nice day")
}

func validateValue(key, expected string, test *testing.T) {
	st := InitSecureStore(FILENAME)
	value, err := st.Get(key)
	if err!=nil {
		test.Error("Failed to get data from storage", err)
	}
	if value!=expected {
		test.Fatalf("Failed to store and retrieve secure data")
	}
}

func Test0testSecureStoreAndLoad(test *testing.T) {
	initializeStorage()
	validateValue("/path1/key1","hello", test)
	validateValue("/path1/key2","world", test)
	validateValue("/path2/key1","have", test)
	validateValue("/path2/key2","a nice day", test)

}
