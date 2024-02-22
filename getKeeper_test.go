package poly_ex

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/ontio/ontology-crypto/keypair"
	vconf "github.com/ontio/ontology/consensus/vbft/config"
	poly_go_sdk "github.com/polynetwork/poly-go-sdk"
	"testing"
)

/*
mainnet keepers 4
120502288bdebfab545852b31638298c7100a9c26ad325f246b0939c661b9b112722c1
12050309d013d6adf0e56e439bde646ea9eff68467fa0a03a16d227d79f98c5a6725f6
120503cf256247dda995ab1ec68ef90865b5d78f6d805339b40e736e913493bb25446d
120503ecb8c0737073522c6f80dd8c7f1d8f0ec19c320010a27f9568bcdebefe8196d4
*/

/*
testnet keepers 4
12050226f22a620ab00e3c5832a12d6e91406bc67ea7b1e9582e800abd921c371074da
1205024e552e00b6a7457d6b79298b449922de987561fe02d420398c862f1447e9231f
120502e3b9e57f97515aa8818b071637f5b42c8c24f864cb6826297f4e0ad78bbf1802
120503b73a7c698594c7e1e1e57746bedc99693130e801500996af39a62ea929d0797d
*/

func Test_getKeeper(t *testing.T) {
	sdk := poly_go_sdk.NewPolySdk()
	sdk.NewRpcClient().SetAddress(MAIN_URL)
	polyHeader, err := sdk.GetHeaderByHeight(uint32(MAIN_BOOKEEPER_HEIGHT))
	if err != nil {
		t.Fatal(err)
	}
	info := &vconf.VbftBlockInfo{}
	err = json.Unmarshal(polyHeader.ConsensusPayload, info)
	if err != nil {
		t.Fatal(err)
	}
	var bks []keypair.PublicKey
	for _, peer := range info.NewChainConfig.Peers {
		keyStr, _ := hex.DecodeString(peer.ID)
		key, _ := keypair.DeserializePublicKey(keyStr)
		bks = append(bks, key)
	}
	bks = keypair.SortPublicKeys(bks)
	var pubKeys []byte
	pubKeys = []byte{}
	for _, key := range bks {
		fmt.Println(hex.EncodeToString(keypair.SerializePublicKey(key)))
	}
	for _, key := range bks {
		var bytes []byte
		bytes, err = EncodePubKey(key)
		if err != nil {
			t.Fatal(err)
		}
		pubKeys = append(pubKeys, bytes...)
	}
	fmt.Println("pubKeyList", hex.EncodeToString(pubKeys))
}
