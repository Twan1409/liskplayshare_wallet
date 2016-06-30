// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"

#include "random.h"
#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>

using namespace std;
using namespace boost::assign;

struct SeedSpec6 {
    uint8_t addr[16];
    uint16_t port;
};

#include "chainparamsseeds.h"

/**
 * Main network
 */

//! Convert the pnSeeds6 array into usable address objects.
static void convertSeed6(std::vector<CAddress> &vSeedsOut, const SeedSpec6 *data, unsigned int count)
{
    // It'll only connect to one or two seed nodes because once it connects,
    // it'll get a pile of addresses with newer timestamps.
    // Seed nodes are given a random 'last seen time' of between one and two
    // weeks ago.
    const int64_t nOneWeek = 7*24*60*60;
    for (unsigned int i = 0; i < count; i++)
    {
        struct in6_addr ip;
        memcpy(&ip, data[i].addr, sizeof(ip));
        CAddress addr(CService(ip, data[i].port));
        addr.nTime = GetTime() - GetRand(nOneWeek) - nOneWeek;
        vSeedsOut.push_back(addr);
    }
}

/**
 * zaobi.org 检测点
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */
static Checkpoints::MapCheckpoints mapCheckpoints =
        boost::assign::map_list_of
        (  0, uint256("0x71f27953344fc76e98f0a46dc2b75f2bde33fb41a8129cc17c982f7299da51a5"))
        ;
static const Checkpoints::CCheckpointData data = {
        &mapCheckpoints,
        1463356800, // * UNIX timestamp of last checkpoint block
        1,   // * total number of transactions between genesis and last checkpoint
                    //   (the tx=... number in the SetBestChain debug.log lines)
        1000.0     // * estimated number of transactions per day after checkpoint
    };

static Checkpoints::MapCheckpoints mapCheckpointsTestnet =
        boost::assign::map_list_of
        ( 546, uint256("0xa0fea99a6897f531600c8ae53367b126824fd6a847b2b2b73817a95b8e27e602"))
        ;
static const Checkpoints::CCheckpointData dataTestnet = {
        &mapCheckpointsTestnet,
        1365458829,
        547,
        576
    };

static Checkpoints::MapCheckpoints mapCheckpointsRegtest =
        boost::assign::map_list_of
        ( 0, uint256("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"))
        ;
static const Checkpoints::CCheckpointData dataRegtest = {
        &mapCheckpointsRegtest,
        0,
        0,
        0
    };

class CMainParams : public CChainParams {
public:
    CMainParams() {
        networkID = CBaseChainParams::MAIN;
        strNetworkID = "main";
        /**
	 * zaobi.org 消息头
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 4-byte int at any alignment.
         */
        pchMessageStart[0] = 0xfb;
        pchMessageStart[1] = 0xc0;
        pchMessageStart[2] = 0xb6;
        pchMessageStart[3] = 0xdb;
        vAlertPubKey = ParseHex("040184710fa689ad5023690c80f3a49c8f13f8d45b8c857fbcbc8bc4a8e4d3eb4b10f4d4604fa08dce601aaf0f470216fe1b51850b4acf21b179c45070ac7b03a9");
        /** zaobi.org P2P 端口*/

        nDefaultPort = 6501;
        bnProofOfWorkLimit = ~uint256(0) >> 16;

        /** zaobi.org 减半间隔块数*/
        nSubsidyHalvingInterval = 840000;
        nEnforceBlockUpgradeMajority = 750;
        nRejectBlockOutdatedMajority = 950;
        nToCheckBlockUpgradeMajority = 1000;
        nMinerThreads = 0;
        /** zaobi.org 难度调整时间间隔 */
	      nTargetTimespan = 30 * 60; // 4 hours
        /** zaobi.org 出块时间间隔*/
	      nTargetSpacing = 1 * 60; // 2.5 minutes
        nMaxTipAge = 30 * 24 * 60 * 60;

        /**
	 * zaobi.org 基因块
         * Build the genesis block. Note that the output of the genesis coinbase cannot
         * be spent as it did not originally exist in the database.
         *
         * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
         *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
         *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
         *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
         *   vMerkleTree: 4a5e1e
         */
        const char* pszTimestamp = "zaobi-genesis-pszTimestamp";
        CMutableTransaction txNew;
        txNew.vin.resize(1);
        txNew.vout.resize(1);
        txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew.vout[0].nValue = 1* COIN;
        txNew.vout[0].scriptPubKey = CScript() << ParseHex("041e0ddf48212a743ebe0bef72fd6bb420e1d49b29a173e554994c1cfec73884d7896bf419d95b6deef6f63bd5f2a8fc662c79e1e4f70f585776d82209cec5aa4c") << OP_CHECKSIG;
        genesis.vtx.push_back(txNew);
        genesis.hashPrevBlock = 0;
        genesis.hashMerkleRoot = genesis.BuildMerkleTree();
        genesis.nVersion = 1;

        genesis.nTime    = 1463356800;
        genesis.nBits    = bnProofOfWorkLimit.GetCompact();
        genesis.nNonce   =  637630;

        hashGenesisBlock = genesis.GetHash();
        //// debug print
        if(hashGenesisBlock != uint256("0x71f27953344fc76e98f0a46dc2b75f2bde33fb41a8129cc17c982f7299da51a5")){

            uint256 powhash=genesis.GetPoWHash();
            while (powhash > bnProofOfWorkLimit){
                if (++genesis.nNonce==0) break;
                LogPrintf("tested nounce %d",genesis.nNonce);
                powhash = genesis.GetPoWHash();
            }

        cout<<"block.GetHash() == 0x"<<genesis.GetHash().ToString().c_str()<<endl;
        cout<<"block.hashMerkleRoot == 0x"<<genesis.hashMerkleRoot.ToString().c_str()<<endl;
        cout<<"block.nTime = "<< genesis.nTime<<endl;
        cout<<"block.nNonce = "<< genesis.nNonce<<endl;
        }

        assert(hashGenesisBlock == uint256("0x71f27953344fc76e98f0a46dc2b75f2bde33fb41a8129cc17c982f7299da51a5"));
        assert(genesis.hashMerkleRoot == uint256("0x0b30d344ecadaddc8c7698ae492afb62f5049b9da127a8c9f16a4b5561ed1ae1"));


	/**
	   zaobi.org 种子节点
	 */
        vSeeds.push_back(CDNSSeedData("zaobi.org1", "120.76.119.214"));
        vSeeds.push_back(CDNSSeedData("zaobi.org2", "123.56.228.200"));
        vSeeds.push_back(CDNSSeedData("zaobi.org", "dnsseed.zaobi.org"));
        vSeeds.push_back(CDNSSeedData("1zaobi.org", "dnsseed1.zaobi.org"));
        vSeeds.push_back(CDNSSeedData("2zaobi.org", "dnsseed2.zaobi.org"));
        vSeeds.push_back(CDNSSeedData("3zaobi.org", "dnsseed3.zaobi.org"));
        vSeeds.push_back(CDNSSeedData("4zaobi.org", "dnsseed4.zaobi.org"));
        vSeeds.push_back(CDNSSeedData("5zaobi.org", "dnsseed5.zaobi.org"));
        vSeeds.push_back(CDNSSeedData("6zaobi.org", "dnsseed6.zaobi.org"));
        vSeeds.push_back(CDNSSeedData("zaobi.org2","120.24.16.145"));
        vSeeds.push_back(CDNSSeedData("zaobi.org3","123.56.228.200"));
        vSeeds.push_back(CDNSSeedData("zaobi.org3","120.76.119.214"));
	/**
	   zaobi.org 地址头字母
	 */
        base58Prefixes[PUBKEY_ADDRESS] = list_of(48);
        base58Prefixes[SCRIPT_ADDRESS] = list_of(5);
        base58Prefixes[SECRET_KEY] =     list_of(176);
        base58Prefixes[EXT_PUBLIC_KEY] = list_of(0x04)(0x88)(0xB2)(0x1E);
        base58Prefixes[EXT_SECRET_KEY] = list_of(0x04)(0x88)(0xAD)(0xE4);

        convertSeed6(vFixedSeeds, pnSeed6_main, ARRAYLEN(pnSeed6_main));

        fRequireRPCPassword = true;
        fMiningRequiresPeers = true;
        fAllowMinDifficultyBlocks = false;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fSkipProofOfWorkCheck = false;
        fTestnetToBeDeprecatedFieldRPC = false;

        // Liskplayshare: Mainnet v2 enforced as of block 710k
        nEnforceV2AfterHeight = 0;
    }

    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return data;
    }
};
static CMainParams mainParams;

/**
 * Testnet (v3)
 */
class CTestNetParams : public CMainParams {
public:
    CTestNetParams() {
        networkID = CBaseChainParams::TESTNET;
        strNetworkID = "test";
        pchMessageStart[0] = 0xfc;
        pchMessageStart[1] = 0xc1;
        pchMessageStart[2] = 0xb7;
        pchMessageStart[3] = 0xdc;
        vAlertPubKey = ParseHex("0449623fc74489a947c4b15d579115591add020e53b3490bf47297dfa3762250625f8ecc2fb4fc59f69bdce8f7080f3167808276ed2c79d297054367566038aa82");

	nDefaultPort = 6504;
        nEnforceBlockUpgradeMajority = 51;
        nRejectBlockOutdatedMajority = 75;
        nToCheckBlockUpgradeMajority = 100;
        nMinerThreads = 0;
	       nTargetTimespan = 3.5 * 24 * 60 * 60; // 3.5 days
	       nTargetSpacing = 2.5 * 60; // 2.5 minutes
        nMaxTipAge = 0x7fffffff;

        //! Modify the testnet genesis block so the timestamp is valid for a later start.
        genesis.nTime = 1458763653;
        genesis.nNonce = 385489580;

        //comment this WHEN debug
        hashGenesisBlock = genesis.GetHash();
        //// debug print
        if(hashGenesisBlock!=uint256("0x0000eb429b2d96366e06adff9b6ac89625bf561d258ad48e28b91dfc39b2e49a")){
            uint256 powhash=genesis.GetHash();
            while (powhash > bnProofOfWorkLimit){
                if (++genesis.nNonce==0) break;
                LogPrintf("tested nounce %d",genesis.nNonce);
                powhash = genesis.GetHash();
            }
            cout<<"TESTNET block.GetHash() == 0x"<<genesis.GetHash().ToString().c_str()<<endl;
            cout<<"TESTNET block.hashMerkleRoot == 0x"<<genesis.hashMerkleRoot.ToString().c_str()<<endl;
            cout<<"TESTNET block.nTime = "<< genesis.nTime<<endl;
            cout<<"TESTNET block.nNonce = "<< genesis.nNonce<<endl;
        }

        assert(hashGenesisBlock == uint256("0x0000eb429b2d96366e06adff9b6ac89625bf561d258ad48e28b91dfc39b2e49a"));

        vFixedSeeds.clear();
        vSeeds.clear();
        vSeeds.push_back(CDNSSeedData("liskplaysharetools.com", "testnet-seed.liskplaysharetools.com"));
        vSeeds.push_back(CDNSSeedData("xurious.com", "testnet-seed.ltc.xurious.com"));
        vSeeds.push_back(CDNSSeedData("wemine-testnet.com", "dnsseed.wemine-testnet.com"));

        base58Prefixes[PUBKEY_ADDRESS] = list_of(111);
        base58Prefixes[SCRIPT_ADDRESS] = list_of(196);
        base58Prefixes[SECRET_KEY]     = list_of(239);
        base58Prefixes[EXT_PUBLIC_KEY] = list_of(0x04)(0x35)(0x87)(0xCF);
        base58Prefixes[EXT_SECRET_KEY] = list_of(0x04)(0x35)(0x83)(0x94);

        convertSeed6(vFixedSeeds, pnSeed6_test, ARRAYLEN(pnSeed6_test));

        fRequireRPCPassword = true;
        fMiningRequiresPeers = true;
        fAllowMinDifficultyBlocks = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = true;

        // Liskplayshare: Testnet v2 enforced as of block 400k
        nEnforceV2AfterHeight = 400000;
    }
    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return dataTestnet;
    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CTestNetParams {
public:
    CRegTestParams() {
        networkID = CBaseChainParams::REGTEST;
        strNetworkID = "regtest";
        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbf;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xda;
        nSubsidyHalvingInterval = 150;
        nEnforceBlockUpgradeMajority = 750;
        nRejectBlockOutdatedMajority = 950;
        nToCheckBlockUpgradeMajority = 1000;
        nMinerThreads = 1;
        nTargetTimespan = 3.5 * 24 * 60 * 60; // 3.5 days
        nTargetSpacing = 2.5 * 60; // 2.5 minutes
        bnProofOfWorkLimit = ~uint256(0) >> 1;
        nMaxTipAge = 24 * 60 * 60;
        genesis.nTime = 1296688602;
        genesis.nBits = 0x207fffff;
        genesis.nNonce = 1;
        hashGenesisBlock = genesis.GetHash();
        nDefaultPort = 19444;

        // //// debug print
        // if(hashGenesisBlock!=uint256("0x0000eb429b2d96366e06adff9b6ac89625bf561d258ad48e28b91dfc39b2e49a")){
        //     uint256 powhash=genesis.GetHash();
        //     while (powhash > bnProofOfWorkLimit){
        //         if (++genesis.nNonce==0) break;
        //         LogPrintf("tested nounce %d",genesis.nNonce);
        //         powhash = genesis.GetHash();
        //     }
        //     cout<<"TESTNET block.GetHash() == 0x"<<genesis.GetHash().ToString().c_str()<<endl;
        //     cout<<"TESTNET block.hashMerkleRoot == 0x"<<genesis.hashMerkleRoot.ToString().c_str()<<endl;
        //     cout<<"TESTNET block.nTime = "<< genesis.nTime<<endl;
        //     cout<<"TESTNET block.nNonce = "<< genesis.nNonce<<endl;
        // }
               cout<<hashGenesisBlock.ToString().c_str()<<endl;
        assert(hashGenesisBlock == uint256("662fc4c6be210085cf142c0c174ddba80cc3a79c53e15f8e7a01352a40e251ef"));

        vFixedSeeds.clear(); //! Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();  //! Regtest mode doesn't have any DNS seeds.

        fRequireRPCPassword = false;
        fMiningRequiresPeers = false;
        fAllowMinDifficultyBlocks = true;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;

        // Liskplayshare: v2 enforced using Bitcoin's supermajority rule
        nEnforceV2AfterHeight = -1;
    }
    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return dataRegtest;
    }
};
static CRegTestParams regTestParams;

/**
 * Unit test
 */
class CUnitTestParams : public CMainParams, public CModifiableParams {
public:
    CUnitTestParams() {
        networkID = CBaseChainParams::UNITTEST;
        strNetworkID = "unittest";
        nDefaultPort = 18445;
        vFixedSeeds.clear(); //! Unit test mode doesn't have any fixed seeds.
        vSeeds.clear();  //! Unit test mode doesn't have any DNS seeds.

        fRequireRPCPassword = false;
        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fAllowMinDifficultyBlocks = false;
        fMineBlocksOnDemand = true;

        // Liskplayshare: v2 enforced using Bitcoin's supermajority rule
        nEnforceV2AfterHeight = -1;
    }

    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        // UnitTest share the same checkpoints as MAIN
        return data;
    }

    //! Published setters to allow changing values in unit test cases
    virtual void setSubsidyHalvingInterval(int anSubsidyHalvingInterval)  { nSubsidyHalvingInterval=anSubsidyHalvingInterval; }
    virtual void setEnforceBlockUpgradeMajority(int anEnforceBlockUpgradeMajority)  { nEnforceBlockUpgradeMajority=anEnforceBlockUpgradeMajority; }
    virtual void setRejectBlockOutdatedMajority(int anRejectBlockOutdatedMajority)  { nRejectBlockOutdatedMajority=anRejectBlockOutdatedMajority; }
    virtual void setToCheckBlockUpgradeMajority(int anToCheckBlockUpgradeMajority)  { nToCheckBlockUpgradeMajority=anToCheckBlockUpgradeMajority; }
    virtual void setDefaultConsistencyChecks(bool afDefaultConsistencyChecks)  { fDefaultConsistencyChecks=afDefaultConsistencyChecks; }
    virtual void setAllowMinDifficultyBlocks(bool afAllowMinDifficultyBlocks) {  fAllowMinDifficultyBlocks=afAllowMinDifficultyBlocks; }
    virtual void setSkipProofOfWorkCheck(bool afSkipProofOfWorkCheck) { fSkipProofOfWorkCheck = afSkipProofOfWorkCheck; }
};
static CUnitTestParams unitTestParams;


static CChainParams *pCurrentParams = 0;

CModifiableParams *ModifiableParams()
{
   assert(pCurrentParams);
   assert(pCurrentParams==&unitTestParams);
   return (CModifiableParams*)&unitTestParams;
}

const CChainParams &Params() {
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams &Params(CBaseChainParams::Network network) {
    switch (network) {
        case CBaseChainParams::MAIN:
            return mainParams;
        case CBaseChainParams::TESTNET:
            return testNetParams;
        case CBaseChainParams::REGTEST:
            return regTestParams;
        case CBaseChainParams::UNITTEST:
            return unitTestParams;
        default:
            assert(false && "Unimplemented network");
            return mainParams;
    }
}

void SelectParams(CBaseChainParams::Network network) {
    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}

bool SelectParamsFromCommandLine()
{
    CBaseChainParams::Network network = NetworkIdFromCommandLine();
    if (network == CBaseChainParams::MAX_NETWORK_TYPES)
        return false;

    SelectParams(network);
    return true;
}
