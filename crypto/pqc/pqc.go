package pqc

import (
	"database/sql"
	"encoding/hex"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/liboqs-go/oqs"
	"github.com/ethereum/go-ethereum/log"
	_ "github.com/go-sql-driver/mysql"
	//"log"
	"time"
)

var signer = oqs.Signature{}
var verifier = oqs.Signature{}

//var sigName = "Falcon-512"
//var sigName = "Falcon-1024"
//var sigName = "Dilithium2"
//var sigName = "Dilithium3"
//var sigName = "Dilithium5"
//var sigName = "Dilithium2-AES"
//var sigName = "Dilithium3-AES"
//var sigName = "Dilithium5-AES"
//var sigName = "Rainbow-I-Classic"
//var sigName = "Rainbow-I-Circumzenithal"
//var sigName = "Rainbow-I-Compressed"
//var sigName = "Rainbow-III-Classic"
//var sigName = "Rainbow-III-Circumzenithal"
//var sigName = "Rainbow-III-Compressed"
//var sigName = "Rainbow-V-Classic"
//var sigName = "Rainbow-V-Circumzenithal"
var sigName = "Rainbow-V-Compressed"

// PQC公钥
type PublicKeyPQC struct {
	Pk []byte
}

// PQC私钥
type PrivateKeyPQC struct {
	PublicKeyPQC
	Sk []byte
}

func Sign(address common.Address, digestHash []byte) (sig []byte, err error) {
	// 用地址找到私钥
	addrStr := address.String()
	db, err := sql.Open("mysql", "test2:0000@tcp(192.168.31.188:3306)/pqc?charset=utf8")
	if err != nil {
		panic(err)
	}
	var skStr string
	row := db.QueryRow("SELECT secretkey FROM addrkey WHERE address = ?", addrStr)
	err = row.Scan(&skStr)
	db.Close()
	// 复原为byte数组
	sk, err := hex.DecodeString(skStr)
	if err != nil {
		panic(err)
	}
	var skStruct PrivateKeyPQC
	skStruct.Sk = sk
	// pqc签名
	return SignPQC(digestHash, &skStruct)
}

func VerifySignature(address common.Address, digestHash, signature []byte) bool {
	// 用地址找到公钥
	addrStr := address.String()
	db, err := sql.Open("mysql", "test2:0000@tcp(192.168.31.188:3306)/pqc?charset=utf8")
	if err != nil {
		panic(err)
	}
	var pkStr string
	row := db.QueryRow("SELECT publickey FROM addrkey WHERE address = ?", addrStr)
	err = row.Scan(&pkStr)
	db.Close()
	// 复原为byte数组
	pk, err := hex.DecodeString(pkStr)
	if err != nil {
		panic(err)
	}
	var pkStruct PublicKeyPQC
	pkStruct.Pk = pk
	return VerifySignaturePQC(&pkStruct, digestHash, signature)
}

func GenerateKey() (*PrivateKeyPQC, error) {
	fmt.Println("----PQC秘钥对生成开始: ", sigName)
	log.Info("----PQC秘钥对生成开始: ", sigName)

	startTime := time.Now()

	defer signer.Clean() // clean up even in case of panic

	if err := signer.Init(sigName, nil); err != nil {
		//log.Fatal(err)
		log.Info(err.Error())
	}

	sk, pk, err := signer.GenerateKeyPairFinal()

	privateKey := new(PrivateKeyPQC)

	privateKey.PublicKeyPQC.Pk = pk
	privateKey.Sk = sk

	endTime := time.Now()
	fmt.Println("----PQC秘钥对生成结束: ", sigName)
	log.Info("----PQC秘钥对生成结束: ", sigName)
	deltaTime := endTime.Sub(startTime)
	fmt.Println("----PQC秘钥对生成时间: ", deltaTime)
	fmt.Println("----PQC公钥长度: ", len(privateKey.Pk))
	fmt.Println("----PQC私钥长度: ", len(privateKey.Sk))
	log.Info("----PQC秘钥对生成时间: ", deltaTime.String())
	log.Info("----PQC公钥长度: ", len(privateKey.Pk))
	log.Info("----PQC私钥长度: ", len(privateKey.Sk))

	// 将记录信息插入到数据库中: 算法名称 + 秘钥对生成时间
	db, err := sql.Open("mysql", "test2:0000@tcp(192.168.31.188:3306)/pqc?charset=utf8")
	if err != nil {
		panic(err)
	}
	stmt, err := db.Prepare("INSERT detailsfar SET sigName = ?, keyGenTime = ?, pkLen = ?, skLen = ?")
	res, err := stmt.Exec(sigName, deltaTime.String(), len(privateKey.Pk), len(privateKey.Sk))
	fmt.Println("----数据库返回结果res == ", res)
	if err != nil {
		fmt.Println("秘钥对信息插入detailsfar失败")
		panic(err)
	}
	db.Close()

	return privateKey, err
}

func SignPQC(digestHash []byte, prv *PrivateKeyPQC) (sig []byte, err error) {
	fmt.Println("----PQC签名开始: ", sigName)
	log.Info("----PQC签名开始: ", sigName)
	startTime := time.Now()

	defer signer.Clean()

	if err := signer.Init(sigName, prv.Sk); err != nil {
		//log.Fatal(err)
		log.Info(err.Error())
	}

	sign, err := signer.Sign(digestHash)

	endTime := time.Now()
	fmt.Println("----PQC签名结束: ", sigName)
	log.Info("----PQC签名结束: ", sigName)
	deltaTime := endTime.Sub(startTime)
	fmt.Println("----PQC签名时间: ", deltaTime)
	fmt.Println("----PQC签名长度: ", len(sign))
	log.Info("----PQC签名时间: ", deltaTime.String())
	log.Info("----PQC签名长度: ", len(sign))

	fmt.Println("数据库插入签名: ")
	db, err := sql.Open("mysql", "test2:0000@tcp(192.168.31.188:3306)/pqc?charset=utf8")
	if err != nil {
		panic(err)
	}
	stmt, err := db.Prepare("INSERT detailsfar SET sigName = ?, sigTime = ?, sigLen = ?")
	res, err := stmt.Exec(sigName, deltaTime.String(), len(sign))
	fmt.Println("----数据库返回结果res == ", res)
	if err != nil {
		fmt.Println("插入数据库detailsfar失败")
		panic(err)
	}
	db.Close()

	return sign, err
}

func VerifySignaturePQC(pubkey *PublicKeyPQC, msg, signature []byte) bool {
	fmt.Println("----PQC验签开始: ", sigName)
	log.Info("----PQC验签开始: ", sigName)
	startTime := time.Now()

	defer verifier.Clean()

	if err := verifier.Init(sigName, nil); err != nil {
		//log.Fatal(err)
		log.Info(err.Error())
	}

	isValid, err := verifier.Verify(msg, signature, pubkey.Pk)
	if err != nil {
		//log.Fatal(err)
		log.Info(err.Error())
	}

	endTime := time.Now()
	fmt.Println("----PQC验签结束: ", sigName)
	log.Info("----PQC验签结束: ", sigName)
	deltaTime := endTime.Sub(startTime)
	fmt.Println("----PQC验签时间: ", deltaTime)
	log.Info("----PQC验签时间: ", deltaTime.String())

	fmt.Println("数据库插入验签: ")
	db, err := sql.Open("mysql", "test2:0000@tcp(192.168.31.188:3306)/pqc?charset=utf8")
	if err != nil {
		panic(err)
	}
	stmt, err := db.Prepare("INSERT detailsfar SET sigName = ?, verTime = ?")
	res, err := stmt.Exec(sigName, deltaTime.String())
	fmt.Println("----数据库返回结果res == ", res)
	if err != nil {
		fmt.Println("插入数据库detailsfar失败")
		panic(err)
	}
	db.Close()
	return isValid
}
