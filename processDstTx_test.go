package poly_ex

import (
	"bytes"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/ethereum/go-ethereum/accounts/abi"
	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ontio/ontology-crypto/ec"
	"github.com/ontio/ontology-crypto/keypair"
	"github.com/ontio/ontology-crypto/signature"
	"github.com/ontio/ontology-crypto/sm2"
	vconf "github.com/ontio/ontology/consensus/vbft/config"
	poly_go_sdk "github.com/polynetwork/poly-go-sdk"
	sdk "github.com/polynetwork/poly-go-sdk"
	common4 "github.com/polynetwork/poly-go-sdk/common"
	common2 "github.com/polynetwork/poly/common"
	"github.com/polynetwork/poly/core/types"
	"github.com/polynetwork/poly/merkle"
	"github.com/polynetwork/poly/native/service/cross_chain_manager/common"
	common3 "github.com/polynetwork/poly/native/service/cross_chain_manager/common"
	"math/big"
	"poly_ex/eccd_abi"
	"poly_ex/eccm_abi"
	"strings"
	"testing"
)

var POLY int = 2

const UINT256_SIZE = 32

var NEO3 uint64 = 14
var NEO uint64 = 4
var ONT uint64 = 3

var GlobalSubmitterMap = make(map[string]*Submitter)
var (
	CrossChainManagerContractAddress, _ = common2.AddressParseFromBytes([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03})
)

type Submitter struct {
	sdk     *ethclient.Client
	polySdk *sdk.PolySdk
	name    string
	ccd     ethcommon.Address
	abi     abi.ABI
	chainId uint64
}

func Test_pplltt(t *testing.T) {
	polyurl := TEST_URL
	polytx := "5c3191df40d7fd247f7dbdf07b1e154dee7db0a3b065a6fdc8e8b927d162e6c6"
	dsteccd := "0x3fea1db1874ac617b1bfc9a840a2739d76c971ca"
	dsturl := "https://testnet.palette-rpc.com:22000"
	dstchainid := uint64(108)
	polysdk := poly_go_sdk.NewPolySdk()
	polysdk.NewRpcClient().SetAddress(polyurl)
	sub := new(Submitter)
	err := sub.Init(dstchainid, []string{}, dsteccd, dsturl, polysdk)
	if err != nil {
		t.Fatal("Init err", err)
	}
	tx, err := sub.GetTx(polytx)
	if err != nil {
		t.Fatal("GetTx err", err)
	}
	proof, rawHeader, headerProof, curRawHeader, headerSig, err := sub.ProcessTx(tx)
	if err != nil {
		t.Fatal("ProcessTx err", err)
	}
	fmt.Println("proof", hex.EncodeToString(proof))
	fmt.Println("rawHeader", hex.EncodeToString(rawHeader))
	fmt.Println("headerProof", hex.EncodeToString(headerProof))
	fmt.Println("curRawHeader", hex.EncodeToString(curRawHeader))
	fmt.Println("headerSig", hex.EncodeToString(headerSig))

	v, err := merkle.MerkleProve(proof, tx.PolyHeader.CrossStateRoot.ToArray())

	s := common2.NewZeroCopySource(v)
	merkleValue := new(common3.ToMerkleValue)
	err = merkleValue.Deserialization(s)
	if err != nil {
		fmt.Println("Deserialization err:", err)
	}
	fmt.Println("FromChainID", merkleValue.FromChainID)
	fmt.Println("ToChainID", merkleValue.MakeTxParam.ToChainID)
	fmt.Println("FromContract", hex.EncodeToString(merkleValue.MakeTxParam.FromContractAddress))
	fmt.Println("ToContract", hex.EncodeToString(merkleValue.MakeTxParam.ToContractAddress))
	fmt.Println("Method", merkleValue.MakeTxParam.Method)
	fmt.Println("args", hex.EncodeToString(merkleValue.MakeTxParam.Args))
}

func (s *Submitter) Init(chainId uint64, nodes []string, ccdContract string, url string, polySdk *sdk.PolySdk) (err error) {
	s.sdk, err = ethclient.Dial(url)
	if err != nil {
		return
	}
	s.name = "plt"
	s.chainId = 108
	s.ccd = ethcommon.HexToAddress(ccdContract)
	s.abi, err = abi.JSON(strings.NewReader(eccm_abi.EthCrossChainManagerABI))
	s.polySdk = polySdk
	return
}

func (s *Submitter) GetTx(polyTxHash string) (tx *Tx, err error) {
	return s.scanTx(polyTxHash)
}

func (s *Submitter) scanTx(hash string) (tx *Tx, err error) {
	//hash hasn't '0x'
	event, err := s.polySdk.GetSmartContractEvent(hash)
	if err != nil {
		return nil, err
	}
	if event == nil {
		err = fmt.Errorf("invalid poly hash %s", hash)
		return
	}
	for _, notify := range event.Notify {
		if notify.ContractAddress == CrossChainManagerContractAddress.ToHexString() {
			states := notify.States.([]interface{})
			if len(states) < 6 {
				continue
			}
			method, _ := states[0].(string)
			if method != "makeProof" {
				continue
			}

			dstChain := uint64(states[2].(float64))
			if dstChain == 0 {
				fmt.Println("Invalid dst chain id in poly tx", "hash", event.TxHash)
				continue
			}

			tx := new(Tx)
			tx.DstChainId = dstChain
			tx.PolyKey = states[5].(string)
			tx.PolyHeight = uint32(states[4].(float64))
			tx.PolyHash = event.TxHash
			tx.TxType = POLY
			tx.TxId = states[3].(string)
			tx.SrcChainId = uint64(states[1].(float64))
			switch tx.SrcChainId {
			case NEO, NEO3, ONT:
				tx.TxId = HexStringReverse(tx.TxId)
			}
			return tx, nil
		}
	}
	return nil, errors.New(fmt.Sprintf("hash:%v hasn't event", hash))
}

func (s *Submitter) GetPolyKeepers() (keepers []byte, err error) {
	ccd, err := eccd_abi.NewEthCrossChainData(s.ccd, s.sdk)
	if err != nil {
		return
	}
	return ccd.GetCurEpochConPubKeyBytes(nil)
}

func (s *Submitter) GetPolyEpochStartHeight() (height uint32, err error) {
	ccd, err := eccd_abi.NewEthCrossChainData(s.ccd, s.sdk)
	if err != nil {
		return
	}
	return ccd.GetCurEpochStartHeight(nil)
}

func (s *Submitter) processPolyTx(tx *Tx) (proof, rawHeader, headerProof, curRawHeader, headerSig []byte, err error) {
	ccd, err := eccd_abi.NewEthCrossChainData(s.ccd, s.sdk)
	if err != nil {
		return
	}
	txId := [32]byte{}
	copy(txId[:], tx.MerkleValue.TxHash[:32])
	exist, err := ccd.CheckIfFromChainTxExist(nil, tx.SrcChainId, txId)
	if err != nil {
		return
	}
	if exist {
		tx.DstHash = ""
		//err = fmt.Errorf(fmt.Sprint("ProcessPolyTx dst tx already relayed, tx id occupied", "chain", s.name, "poly_hash", tx.PolyHash))
		//return
	}
	headerProof, err = hex.DecodeString(tx.AnchorProof)
	if err != nil {
		return
	}

	if tx.AnchorHeader != nil {
		curRawHeader = tx.AnchorHeader.GetMessage()
	}
	proof, err = hex.DecodeString(tx.AuditPath)
	if err != nil {
		return
	}
	rawHeader = tx.PolyHeader.GetMessage()
	headerSig = tx.PolySigs
	return
}

func (s *Submitter) ProcessTx(m *Tx) (proof, rawHeader, headerProof, curRawHeader, headerSig []byte, err error) {
	m.DstPolyEpochStartHeight, err = s.GetPolyEpochStartHeight()
	if err != nil {
		err = fmt.Errorf("%s fetch dst chain poly epoch height error %v", s.name, err)
		return
	}
	m.DstPolyKeepers, err = s.GetPolyKeepers()
	if err != nil {
		err = fmt.Errorf("%s fetch dst chain poly keepers error %v", s.name, err)
		return
	}
	err = s.ComposeTx(m)
	if err != nil {
		return
	}
	return s.processPolyTx(m)
}

func (s *Submitter) GetProof(height uint32, key string) (param *common3.ToMerkleValue, auditPath string, evt *common4.SmartContactEvent, err error) {
	return s.getProof(height, key)
}

func (s *Submitter) getProof(height uint32, key string) (param *common3.ToMerkleValue, auditPath string, evt *common4.SmartContactEvent, err error) {
	proof, err := s.polySdk.GetCrossStatesProof(height, key)
	if err != nil {
		err = fmt.Errorf("GetProof: GetCrossStatesProof key %s, error %v", key, err)
		return
	}
	auditPath = proof.AuditPath
	path, err := hex.DecodeString(proof.AuditPath)
	if err != nil {
		return
	}
	value, _, _, _ := ParseAuditPath(path)
	param = new(common3.ToMerkleValue)
	err = param.Deserialization(common2.NewZeroCopySource(value))
	if err != nil {
		err = fmt.Errorf("GetPolyParams: param.Deserialization error %v", err)
	}
	return
}

func ParseAuditPath(path []byte) (value []byte, pos []byte, hashes [][32]byte, err error) {
	source := common2.NewZeroCopySource(path)
	value, eof := source.NextVarBytes()
	if eof {
		return
	}
	size := int((source.Size() - source.Pos()) / UINT256_SIZE)
	pos = []byte{}
	hashes = [][32]byte{}
	for i := 0; i < size; i++ {
		f, eof := source.NextByte()
		if eof {
			return
		}
		pos = append(pos, f)

		v, eof := source.NextHash()
		if eof {
			return
		}
		var hash [32]byte
		copy(hash[:], v.ToArray()[0:32])
		hashes = append(hashes, hash)
	}
	return
}

func (s *Submitter) GetPolyParams(tx *Tx) (param *common3.ToMerkleValue, path string, evt *common4.SmartContactEvent, err error) {
	if tx.PolyHash == "" {
		err = fmt.Errorf("ComposeTx: Invalid poly hash")
		return
	}

	if tx.PolyHeight == 0 {
		tx.PolyHeight, err = s.polySdk.GetBlockHeightByTxHash(tx.PolyHash)
		if err != nil {
			return
		}
	}

	if tx.PolyKey != "" {
		return s.GetProof(tx.PolyHeight, tx.PolyKey)
	}

	evt, err = s.polySdk.GetSmartContractEvent(tx.PolyHash)
	if err != nil {
		return
	}

	for _, notify := range evt.Notify {
		if notify.ContractAddress == CrossChainManagerContractAddress.ToHexString() {
			states := notify.States.([]interface{})
			if len(states) > 5 {
				method, _ := states[0].(string)
				if method == "makeProof" {
					param, path, evt, err = s.GetProof(tx.PolyHeight, states[5].(string))
					if err != nil {
						fmt.Println("GetPolyParams: param.Deserialization error", "err", err)
					} else {
						return
					}
				}
			}
		}
	}
	err = fmt.Errorf("Valid ToMerkleValue not found")
	return
}

func (s *Submitter) ComposeTx(tx *Tx) (err error) {
	if tx.PolyHash == "" {
		return fmt.Errorf("ComposeTx: Invalid poly hash")
	}

	if tx.PolyHeight == 0 {
		tx.PolyHeight, err = s.polySdk.GetBlockHeightByTxHash(tx.PolyHash)
		if err != nil {
			return
		}
	}
	tx.PolyHeader, err = s.polySdk.GetHeaderByHeight(tx.PolyHeight + 1)
	if err != nil {
		return fmt.Errorf("GetHeaderByHeight err: %f", err)
	}

	if tx.DstChainId != ONT {
		err = s.ComposePolyHeaderProof(tx)
		if err != nil {
			return
		}
	}

	tx.MerkleValue, tx.AuditPath, _, err = s.GetPolyParams(tx)
	if err != nil {
		return err
	}

	tx.SrcProxy = ethcommon.BytesToAddress(tx.MerkleValue.MakeTxParam.FromContractAddress).String()
	tx.DstProxy = ethcommon.BytesToAddress(tx.MerkleValue.MakeTxParam.ToContractAddress).String()
	s.CollectSigs(tx)
	return
}

func (s *Submitter) CollectSigs(tx *Tx) (err error) {
	var (
		sigs []byte
	)
	sigHeader := tx.PolyHeader
	if tx.AnchorHeader != nil && tx.AnchorProof != "" {
		sigHeader = tx.AnchorHeader
	}
	for _, sig := range sigHeader.SigData {
		temp := make([]byte, len(sig))
		copy(temp, sig)
		s, err := signature.ConvertToEthCompatible(temp)
		if err != nil {
			return fmt.Errorf("MakeTx signature.ConvertToEthCompatible %v", err)
		}
		sigs = append(sigs, s...)
	}
	tx.PolySigs = sigs
	return
}

func (s *Submitter) ComposePolyHeaderProof(tx *Tx) (err error) {
	var anchorHeight uint32
	if tx.PolyHeight < tx.DstPolyEpochStartHeight {
		anchorHeight = tx.DstPolyEpochStartHeight + 1
	} else {
		isEpoch, _, err := s.CheckEpoch(tx, tx.PolyHeader)
		if err != nil {
			return err
		}
		if isEpoch {
			anchorHeight = tx.PolyHeight + 2
		}
	}

	if anchorHeight > 0 {
		tx.AnchorHeader, err = s.polySdk.GetHeaderByHeight(anchorHeight)
		if err != nil {
			return err
		}
		proof, err := s.polySdk.GetMerkleProof(tx.PolyHeight+1, anchorHeight)
		if err != nil {
			return err
		}
		tx.AnchorProof = proof.AuditPath
	}
	return
}

func (s *Submitter) CheckEpoch(tx *Tx, hdr *types.Header) (epoch bool, pubKeys []byte, err error) {
	if tx.DstChainId == NEO {
		return
	}
	if len(tx.DstPolyKeepers) == 0 {
		// err = fmt.Errorf("Dst chain poly keeper not provided")
		return
	}
	if hdr.NextBookkeeper == common2.ADDRESS_EMPTY {
		return
	}
	info := &vconf.VbftBlockInfo{}
	err = json.Unmarshal(hdr.ConsensusPayload, info)
	if err != nil {
		err = fmt.Errorf("CheckEpoch consensus payload unmarshal error %v", err)
		return
	}
	var bks []keypair.PublicKey
	for _, peer := range info.NewChainConfig.Peers {
		keyStr, _ := hex.DecodeString(peer.ID)
		key, _ := keypair.DeserializePublicKey(keyStr)
		bks = append(bks, key)
	}
	bks = keypair.SortPublicKeys(bks)
	pubKeys = []byte{}
	sink := common2.NewZeroCopySink(nil)
	sink.WriteUint64(uint64(len(bks)))
	for _, key := range bks {
		var bytes []byte
		bytes, err = EncodePubKey(key)
		if err != nil {
			return
		}
		pubKeys = append(pubKeys, bytes...)
		bytes, err = EncodeEthPubKey(key)
		if err != nil {
			return
		}
		sink.WriteVarBytes(crypto.Keccak256(bytes[1:])[12:])
	}
	epoch = !bytes.Equal(tx.DstPolyKeepers, sink.Bytes())
	return
}

type Tx struct {
	TxType   int
	Attempts int

	TxId        string                `json:",omitempty"`
	MerkleValue *common.ToMerkleValue `json:"-"`
	Param       *common.MakeTxParam   `json:"-"`

	SrcHash        string `json:",omitempty"`
	SrcHeight      uint64 `json:",omitempty"`
	SrcChainId     uint64 `json:",omitempty"`
	SrcProof       []byte `json:"-"`
	SrcProofHex    string `json:",omitempty"`
	SrcEvent       []byte `json:"-"`
	SrcProofHeight uint64 `json:",omitempty"`
	SrcParam       string `json:",omitempty"`
	SrcStateRoot   []byte `json:"-"`
	SrcProxy       string `json:",omitempty"`
	SrcAddress     string `json:",omitempty"`

	PolyHash     string        `json:",omitempty"`
	PolyHeight   uint32        `json:",omitempty"`
	PolyKey      string        `json:",omitempty"`
	PolyHeader   *types.Header `json:"-"`
	AnchorHeader *types.Header `json:"-"`
	AnchorProof  string        `json:",omitempty"`
	AuditPath    string        `json:"-"`
	PolySigs     []byte        `json:"-"`

	DstAddress              string      `json:",omitempty"`
	DstHash                 string      `json:",omitempty"`
	DstHeight               uint64      `json:",omitempty"`
	DstChainId              uint64      `json:",omitempty"`
	DstGasLimit             uint64      `json:",omitempty"`
	DstGasPrice             string      `json:",omitempty"`
	DstGasPriceX            string      `json:",omitempty"`
	DstSender               interface{} `json:"-"`
	DstPolyEpochStartHeight uint32      `json:",omitempty"`
	DstPolyKeepers          []byte      `json:"-"`
	DstData                 []byte      `json:"-"`
	DstProxy                string      `json:",omitempty"`
	SkipCheckFee            bool        `json:",omitempty"`
	CheckFeeOff             bool        `json:"-"` // CheckFee disabled in submitter
	Skipped                 bool        `json:",omitempty"`
	PaidGas                 float64     `json:",omitempty"`
	DstAsset                string      `json:"-"`
	DstAmount               *big.Int    `json:"-"`

	// aptos
	ToAssetAddress string `json:",omitempty"`

	Extra interface{} `json:"-"`
}

func EncodePubKey(key keypair.PublicKey) ([]byte, error) {
	var buf bytes.Buffer
	switch t := key.(type) {
	case *ec.PublicKey:
		switch t.Algorithm {
		case ec.ECDSA:
			// Take P-256 as a special case
			if t.Params().Name == elliptic.P256().Params().Name {
				return ec.EncodePublicKey(t.PublicKey, false), nil
			}
			buf.WriteByte(byte(0x12))
		case ec.SM2:
			buf.WriteByte(byte(0x13))
		}
		label, err := GetCurveLabel(t.Curve.Params().Name)
		if err != nil {
			return nil, fmt.Errorf("EncodePubKey %v", err)
		}
		buf.WriteByte(label)
		buf.Write(ec.EncodePublicKey(t.PublicKey, false))
	case ed25519.PublicKey:
		return nil, fmt.Errorf("EncodePubKey: ed25519.PublicKey?")
	default:
		return nil, fmt.Errorf("EncodePubKey: unknown key type")
	}
	return buf.Bytes(), nil
}
func EncodeEthPubKey(key keypair.PublicKey) ([]byte, error) {
	switch t := key.(type) {
	case *ec.PublicKey:
		return crypto.FromECDSAPub(t.PublicKey), nil
	case ed25519.PublicKey:
		return nil, fmt.Errorf("EncodeEthPubKey: ed25519.PublicKey?")
	default:
		return nil, fmt.Errorf("EncodeEthPubKey: Unkown key type?")
	}
}
func GetCurveLabel(name string) (byte, error) {
	switch strings.ToUpper(name) {
	case strings.ToUpper(elliptic.P224().Params().Name):
		return 1, nil
	case strings.ToUpper(elliptic.P256().Params().Name):
		return 2, nil
	case strings.ToUpper(elliptic.P384().Params().Name):
		return 3, nil
	case strings.ToUpper(elliptic.P521().Params().Name):
		return 4, nil
	case strings.ToUpper(sm2.SM2P256V1().Params().Name):
		return 20, nil
	case strings.ToUpper(btcec.S256().Name):
		return 5, nil
	default:
		return 0, fmt.Errorf("GetCurveLabel: unknown labelname %s", name)
	}
}
