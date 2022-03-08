package main

import (
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"math/big"
)

func main() {
	// 1. ABI编码请求参数
	methodId := crypto.Keccak256([]byte("setA(uint256)"))[:4]
	fmt.Println("methodId: ", common.Bytes2Hex(methodId))
	paramValue := math.U256Bytes(new(big.Int).Set(big.NewInt(123)))
	fmt.Println("paramValue: ", common.Bytes2Hex(paramValue))
	input := append(methodId, paramValue...)
	fmt.Println("input: ", common.Bytes2Hex(input))
	fmt.Println("1. ABI编码请求参数结束")

	// 2. 构造交易对象
	nonce := uint64(24)
	value := big.NewInt(0)
	gasLimit := uint64(3000000)
	gasPrice := big.NewInt(20000000000)
	rawTx := types.NewTransaction(nonce, common.HexToAddress("0x05e56888360ae54acf2a389bab39bd41e3934d2b"), value, gasLimit, gasPrice, input)
	jsonRawTx, _ := rawTx.MarshalJSON()
	fmt.Println("rawTx: ", string(jsonRawTx))
	fmt.Println("2. 构造交易对象结束")

	// 3. 交易签名
	signer := types.NewEIP155Signer(new(big.Int).SetInt64(8))
	key, err := crypto.HexToECDSA("e8e14120bb5c085622253540e886527d24746cd42d764a5974be47090d3cbc42")
	fmt.Println("addr: ", crypto.PubkeyToAddress(key.PublicKey))

	fmt.Println("pk: ", key.PublicKey)
	if err != nil {
		fmt.Println("crypto.HexToECDSA failed: ", err.Error())
		return
	}

	sigTransaction, err := types.SignTx(rawTx, signer, key)
	fmt.Println()
	//fmt.Println("tx-inner: ", sigTransaction.RawSignaturePQC())
	if err != nil {
		fmt.Println("types.SignTx failed: ", err.Error())
		return
	}
	jsonSigTx, _ := sigTransaction.MarshalJSON()
	fmt.Println("sigTransaction: ", string(jsonSigTx))
	fmt.Println("3. 交易签名结束")

	// 4. 交易验签
	from, err := types.Sender(signer, sigTransaction)
	if err != nil {
		fmt.Println("types.Sender: ", err.Error())
		return
	}
	fmt.Println("from: ", from.Hex())
	fmt.Println("4. 交易验签结束")
}

//func main() {
//	//client, err := ethclient.Dial("http://localhost:8545") // 8000=geth RPC port
//	//if err != nil {
//	//	fmt.Println("client connection error:")
//	//	panic(err)
//	//}
//	//fmt.Println("client connected: ", client)
//	start := time.Now()
//	sum := 0
//	for i := 0; i <= 1000; i++ {
//		sum += i
//	}
//	end := time.Now()
//
//	delta := end.Sub(start)
//	fmt.Println(delta.String())
//	fmt.Println(delta.Nanoseconds())
//	fmt.Println(delta.Milliseconds())
//	fmt.Println(delta.Microseconds())
//	fmt.Println(delta.Seconds())
//}
