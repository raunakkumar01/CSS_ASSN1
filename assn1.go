package assn1

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.
//
import (

	// You neet to add with
	// go get github.com/sarkarbidya/CS628-assn1/userlib

	"github.com/sarkarbidya/CS628-assn1/userlib"

	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...

	"encoding/json"

	// Likewise useful for debugging etc
	"encoding/hex"

	// UUIDs are generated right based on the crypto RNG
	// so lets make life easier and use those too...
	//
	// You need to add with "go get github.com/google/uuid"
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys
	"strings"

	// Want to import errors
	"errors"
)

// This serves two purposes: It shows you some useful primitives and
// it suppresses warnings for items not being imported
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// test
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var key *userlib.PrivateKey
	key, _ = userlib.GenerateRSAKey()
	userlib.DebugMsg("Key is %v", key)
}

var configBlockSize = 4096  //Do not modify this variable 

//setBlockSize - sets the global variable denoting blocksize to the passed parameter. This will be called only once in the beginning of the execution 
func setBlockSize(blocksize int) {
	configBlockSize = blocksize
}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

//User : User structure used to store the user information
type User struct {
	Username string
	Privatekey *userlib.PrivateKey
	Argon []byte
	Key_size int

}

func atoi(c string) (i int) {

	for j:=0;j<len(c);j++ {
		i=i*10+(int(c[j])-48)
	}
	return 

}
func itoa(i int) (str string) {
	j := i
	count := 0
	for j>0 {
		count++;

		j/=10
	}
	//fmt.Println(count)
	arr := make([]byte,count)
	for p:=count-1;p>=0;p--{
		arr[p]=byte(i%10+48)
		i/=10
	}
	return string(arr)
} 


func (userdata *User) getK(file string) (k1 string, k2 string, k3 string){

filename := []byte(file)


username := []byte(userdata.Username)
password := userdata.Argon

file_key := make([]byte,len(filename)+len(password))
enc_key := make([]byte,len(filename)+len(username))
iv_loc := make([]byte,len(filename)+len(username)+len(password))


for i:=0;i<len(filename);i++{
	file_key[i]=filename[i]
}

for i:=0;i<len(password);i++{
	file_key[i+len(filename)]=password[i]
}


for i:=0;i<len(filename);i++{
	enc_key[i]=filename[i]
}

for i:=0;i<len(username);i++{
	enc_key[i+len(filename)]=username[i]
}

for i:=0;i<len(filename);i++{
	iv_loc[i]=filename[i]
}

for i:=0;i<len(username);i++{
	iv_loc[i+len(filename)]=username[i]
}

for i:=0;i<len(password);i++{
	iv_loc[i+len(filename)+len(username)]=password[i]
}

h := userlib.NewSHA256()
h.Write(file_key)
k1 = string(h.Sum(nil))

h = userlib.NewSHA256()
h.Write(enc_key)
k2 = string(h.Sum(nil))

h = userlib.NewSHA256()
h.Write(iv_loc)
k3 = string(h.Sum(nil))

return


}



func getvalues(k1 string, k2 string, k3 string) (file_key []byte, enc_key []byte, ivmac []byte){
	file_key,_ = userlib.DatastoreGet(k1)
	enc_key,_ = userlib.DatastoreGet(k2)
	iv_loc,_ := userlib.DatastoreGet(k3)
	ivmac,_ = userlib.DatastoreGet(string(iv_loc))

	return 
}


// StoreFile : function used to create a  file
// It should store the file in blocks only if length 
// of data []byte is a multiple of the blocksize; if
// this is not the case, StoreFile should return an error.
func (userdata *User) StoreFile(filename string, data []byte) (err error) {

if len(data)%configBlockSize!=0 {
	return errors.New("Data must be multiple of blocksize")
}

k1,k2,k3 := userdata.getK(filename)
file_key := userlib.RandomBytes(32)
enc_key := userlib.RandomBytes(userlib.AESKeySize)
iv_loc := userlib.RandomBytes(32)

userlib.DatastoreSet(k1,file_key)
userlib.DatastoreSet(k2,enc_key)
userlib.DatastoreSet(k3,iv_loc)


ivmac := userlib.RandomBytes(800*userlib.AESKeySize+800*32) ///32 for hmac size






num_keys_per_block := (configBlockSize/32)
num_blocks := len(data)/configBlockSize
root := userlib.RandomBytes(32*num_keys_per_block)



num_block_byte := []byte(itoa(num_blocks))


var j,i int
for j =0;j<len(num_block_byte);j++ {
	root[j]=num_block_byte[j]
}

for i = j;i<32;i++ {
	root[i]=0
}




for i := 1;i<num_keys_per_block; i++ {
	second_level := userlib.RandomBytes(32*num_keys_per_block)
	userlib.DatastoreSet(string(root[i*32:(i+1)*32]),second_level)	
}


for i:=0;i<num_blocks;i++ {
	first_level_index := i/num_keys_per_block+1
	second_level_index := i%num_keys_per_block
	second,_ := userlib.DatastoreGet(string(root[first_level_index*32:(first_level_index+1)*32]))


	curr_block := data[i*configBlockSize:(i+1)*configBlockSize]
	cipher_block := make([]byte,len(curr_block))
	stream := userlib.CFBEncrypter(enc_key, ivmac[i*userlib.AESKeySize:(i+1)*userlib.AESKeySize])
	stream.XORKeyStream(cipher_block,curr_block) 
	h := userlib.NewHMAC(ivmac[i*userlib.AESKeySize:(i+1)*userlib.AESKeySize])
	h.Write(cipher_block)
	mac:= h.Sum(nil) 

	for j:=0;j<32;j++ {
		ivmac[800*userlib.AESKeySize+i*32+j] = mac[j]
	}
	userlib.DatastoreSet(string(second[second_level_index*32:(second_level_index+1)*32]),cipher_block)

}

userlib.DatastoreSet(string(iv_loc),ivmac)
userlib.DatastoreSet(string(file_key),root) 

return
}

//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need. The length of data []byte must be a multiple of
// the block size; if it is not, AppendFile must return an error.
// AppendFile : Function to append the file
func (userdata *User) AppendFile(filename string, data []byte) (err error) {

	k1,k2,k3 := userdata.getK(filename)
	file_key,enc_key,ivmac := getvalues(k1,k2,k3)
	iv_loc,_ := userlib.DatastoreGet(k3)



	num_keys_per_block := (configBlockSize/32)
	root,_ := userlib.DatastoreGet(string(file_key))


	var count int

	for count =0; count<32; count++ {
		if root[count] == 0 {
			break	
		}
	}

	file_size_bytes := make([]byte, count)

	for i :=0; i<count; i++ {
		file_size_bytes[i]=root[i]
	}

	file_size := atoi(string(file_size_bytes))



	num_blocks := len(data)/configBlockSize

	for i:=0;i<num_blocks;i++ {
		first_level_index := file_size/num_keys_per_block+1
		second,_ := userlib.DatastoreGet(string(root[first_level_index*32:(first_level_index+1)*32]))
		second_level_index := file_size%num_keys_per_block

		curr_block := data[i*configBlockSize:(i+1)*configBlockSize]
		cipher_block := make([]byte,len(curr_block))
		stream := userlib.CFBEncrypter(enc_key, ivmac[file_size*userlib.AESKeySize:(file_size+1)*userlib.AESKeySize])
		stream.XORKeyStream(cipher_block,curr_block) 

		h := userlib.NewHMAC(ivmac[file_size*userlib.AESKeySize:(file_size+1)*userlib.AESKeySize])
		h.Write(cipher_block)
		mac := h.Sum(nil)
		for j:=0;j<32;j++ {
			ivmac[800*userlib.AESKeySize+file_size*32+j] = mac[j]
		}
		
		userlib.DatastoreSet(string(second[second_level_index*32:(second_level_index+1)*32]),cipher_block)
	
		file_size += 1
	}


	var j,i int
	file_size_bytes = []byte(itoa(file_size))

	for j =0;j<len(file_size_bytes);j++ {
		root[j]=file_size_bytes[j]
	}
	for i = j;i<32;i++ {
		root[i]=0
	}

	userlib.DatastoreSet(string(iv_loc),ivmac)
	userlib.DatastoreSet(string(file_key),root)

	return
}

// LoadFile :This loads a block from a file in the Datastore.
//
// It should give an error if the file block is corrupted in any way.
// If there is no error, it must return exactly one block (of length blocksize)
// of data.
// 
// LoadFile is also expected to be efficient. Reading a random block from the
// file should not fetch more than O(1) blocks from the Datastore.
func (userdata *User) LoadFile(filename string, offset int) (data []byte, err error) {
	
	k1,k2,k3 := userdata.getK(filename)
	file_key,enc_key,ivmac := getvalues(k1,k2,k3)
	iv_loc,_ := userlib.DatastoreGet(k3)

	num_keys_per_block := (configBlockSize/32)
	root,ok := userlib.DatastoreGet(string(file_key))
	if !ok {
		//fmt.Prinln("file not found")
		return make([]byte,0),errors.New("No file found")
	}

	first_level_index := offset/num_keys_per_block+1
	second,_ := userlib.DatastoreGet(string(root[first_level_index*32:(first_level_index+1)*32]))
	second_level_index := offset%num_keys_per_block

	data,_ = userlib.DatastoreGet(string(second[second_level_index*32:(second_level_index+1)*32]))

	h := userlib.NewHMAC(ivmac[offset*userlib.AESKeySize:(offset+1)*userlib.AESKeySize])
	h.Write(data)
	mac := h.Sum(nil)


	if userlib.Equal(mac,ivmac[800*userlib.AESKeySize+offset*32:800*userlib.AESKeySize+(offset+1)*32]) == false {
		return make([]byte,0),errors.New("Integrity violated") //////////dekhis pore ekbar
	}



	stream := userlib.CFBDecrypter(enc_key, ivmac[offset*userlib.AESKeySize:(offset+1)*userlib.AESKeySize])
	stream.XORKeyStream(data, data)
	ret_data:= data

	new_iv := userlib.RandomBytes(userlib.AESKeySize)
	for i:=0;i<userlib.AESKeySize;i++{
		ivmac[offset*userlib.AESKeySize+i]=new_iv[i];
	}

	cipher_block := make([]byte,configBlockSize)
	stream = userlib.CFBEncrypter(enc_key, ivmac[offset*userlib.AESKeySize:(offset+1)*userlib.AESKeySize])
	stream.XORKeyStream(cipher_block,data)
	userlib.DatastoreSet(string(second[second_level_index*32:(second_level_index+1)*32]),cipher_block)


	h = userlib.NewHMAC(ivmac[offset*userlib.AESKeySize:(offset+1)*userlib.AESKeySize])
	h.Write(cipher_block)
	mac = h.Sum(nil)
	for i:=0;i<32;i++ {
		ivmac[800*userlib.AESKeySize+offset*32+i]=mac[i]
	}



	userlib.DatastoreSet(string(iv_loc),ivmac)


	return ret_data, errors.New("none")
}

// ShareFile : Function used to the share file with other user
func (userdata *User) ShareFile(filename string, recipient string) (msgid string, err error) {

	k1,k2,k3 := userdata.getK(filename)
	record := new(sharingRecord)
	a,_ := userlib.DatastoreGet(k1)
	b,_ := userlib.DatastoreGet(k2)
	c,_ := userlib.DatastoreGet(k3)

	record.File_key = a
	record.Enc_key = b
	record.Iv_loc = c
	//private, _ := GenerateRSAKey()
//if err != nil {}


	//public := &private.PublicKey
//fmt.Println(public)
	sharing,_ := json.Marshal(record)
	public,_ := userlib.KeystoreGet(recipient)
	//fmt.Println(string(sharing))
	//fmt.Println(public)
	msg,_ := userlib.RSAEncrypt(&public,sharing,[]byte(itoa(configBlockSize)))

	msgid = string(msg)
	//fmt.Println(msgid)


	return 
}

// ReceiveFile : function used to receive the file details from the sender
func (userdata *User) ReceiveFile(filename string, sender string, msgid string) error {
	
	back,_ := userlib.RSADecrypt(userdata.Privatekey,[]byte(msgid),[]byte(itoa(configBlockSize)))
	k1,k2,k3 := userdata.getK(filename)
	record := new(sharingRecord)
	json.Unmarshal(back,&record)
	userlib.DatastoreSet(k1,record.File_key)
	userlib.DatastoreSet(k2,record.Enc_key)
	userlib.DatastoreSet(k3,record.Iv_loc)

return errors.New("No error")


}

// RevokeFile : function used revoke the shared file access
func (userdata *User) RevokeFile(filename string) (err error) {

	k1,k2,k3 := userdata.getK(filename)
	file_key,_,_ := getvalues(k1,k2,k3)


	root,_ := userlib.DatastoreGet(string(file_key))



	var count int

	for count =0; count<32; count++ {
		if root[count] == 0 {
			break	
		}
	}

	file_size_bytes := make([]byte, count)
	for i :=0; i<count; i++ {
		file_size_bytes[i]=root[i]
	}

	file_size := atoi(string(file_size_bytes))
	file_data := make([]byte,file_size*configBlockSize)

	for i := 0;i<file_size;i++{
		dat,_ := userdata.LoadFile(filename,i)
		for j:=0;j<configBlockSize;j++{
			file_data[i*configBlockSize+j]=dat[j]
		}
	}
	userlib.DatastoreDelete(string(file_key)) 

	userdata.StoreFile(filename,file_data[0:configBlockSize])

	for i:=1;i<file_size;i++ {
		//data,_ := userdata.LoadFile(filename,i)
		userdata.AppendFile(filename,file_data[i*configBlockSize:(i+1)*configBlockSize])
	}




return
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.
// You may want to define what you actually want to pass as a
// sharingRecord to serialized/deserialize in the data store.
type sharingRecord struct {

	File_key []byte
	Enc_key  []byte
	Iv_loc []byte


}

// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored
// User data: the name used in the datastore should not be guessable
// without also knowing the password and username.
// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// You can assume the user has a STRONG password

//InitUser : function used to create user

func InitUser(username string, password string) (userdataptr *User, err error) {

	userdataptr = new(User)
	
	/// generate username and password
	Argon := userlib.Argon2Key([]byte(password),[]byte(itoa(configBlockSize)),32)
	
	h := userlib.NewSHA256()
	h.Write([]byte(username))
	hashed_username := h.Sum(nil)


	/// store values

	userdataptr.Argon = Argon
	userdataptr.Username = string(hashed_username)
	userdataptr.Key_size = 32

	private, _ := userlib.GenerateRSAKey()
	userdataptr.Privatekey = private
	public := private.PublicKey

	
	userlib.DatastoreSet(string(Argon),hashed_username)
	userlib.KeystoreSet(username,public)

	pass_user := make([]byte,len(Argon)+len(hashed_username))
	for i := 0;i<len(Argon);i++{
		pass_user[i]=Argon[i]; 
	}
	for i := 0;i<len(hashed_username);i++{	
	pass_user[len(Argon)+i]=hashed_username[i]; 
	}


	///store the user struct 
	b,err := json.Marshal(userdataptr)
	if err!=nil{}
	userlib.DatastoreSet(string(pass_user),b)

	return	userdataptr,errors.New("None")
}

// GetUser : This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
//GetUser : function used to get the user details

func equal(a []byte, b []byte) bool {
    if len(a) != len(b) {
        return false
    }
    for i, x := range b {
        if x != a[i] {
            return false
        }
    }
    return true
}


func GetUser(username string, password string) (userdataptr *User, err error) {
	//userdataptr = new(User)

	Argon_r := userlib.Argon2Key([]byte(password),[]byte(itoa(configBlockSize)),32)
	usr_r,ok := userlib.DatastoreGet(string(Argon_r))
	if !ok || usr_r == nil {		
		return userdataptr,errors.New("Error");
	}

	h := userlib.NewSHA256()
	h.Write([]byte(username))
	hashed_username := h.Sum(nil)
	
	var s bool = equal(hashed_username,usr_r)
	if  s == true {
		pass_user := make([]byte,len(Argon_r)+len(hashed_username))
		for i := 0;i<len(Argon_r);i++{
			pass_user[i]=Argon_r[i]; 
		}
		for i := 0;i<len(hashed_username);i++{	
			pass_user[len(Argon_r)+i]=hashed_username[i]; 
		}

		b,ok := userlib.DatastoreGet(string(pass_user))
		if ok == true {}  
		json.Unmarshal(b, &userdataptr)
				
		return userdataptr,errors.New("None")
	}else{	
	return userdataptr,errors.New("Error");
	}
}



