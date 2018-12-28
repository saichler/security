# security
A Simple Encryption and Descyption utils for Habitat including a simple secure storage.

## Example of Secure Storage adding
    secureStore := InitSecureStore("./storage.dat")
    secureStore.Put("mykey1","my")
    secureStore.Put("mykey2", "secure")
    secureStore.Put("mykey3", "storage")
    secureStore.Put("mykey4","simple")
    
## Example of Secure Storage Getting
    secureStore := InitSecureStore("./storage.dat")
    value, err := secureStore.Get("mykey3")
    if err!=nil {
      fmt.Println("Error, Failed to fetch key")
      return
    }
    fmt.Println("value="+value)
