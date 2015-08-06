// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"

#include "random.h"

#include "utilstrencodings.h"
#include "crypto/scrypt.h"
#include "chain.h"

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
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */
static Checkpoints::MapCheckpoints mapCheckpoints =
        boost::assign::map_list_of
        (   100, uint256("0x722978629f5714f55eab4f5e6f03bed10c6bf34d9e73f79566c3eb0b94887c42"))
        (  1000, uint256("0xfd51dbe8a3874a2ff717af63733c19c134f921ecfe0e9bfc74cf80e9ccf97b12"))
        ( 10000, uint256("0xd4702398032bc5b7b3c2e971de88eb6a5d91474350ccf9fdc276b606748eed40"))
        ( 50000, uint256("0xb105dfb1ea9a486e73b502ccf71aec00ff3b6aee994dadd4f7f35e15a21c94e8"))
        (100000, uint256("0x10e02fc59b6e9d3010f0a91da8890fc6bacb59cebb38bdaad8b7f84df68fa617"))
        (136700, uint256("0x56635b3326e9a29f5ad82884eb3cfb7412a7c0daf671174daea834a0a4e80cb6"))
        (175000, uint256("0x1ea14545346fa619ff26000f50eb53f76bfb4861066ef8753c584e752db5b59f"))
        (200000, uint256("0xfc6fbe48af986b7c5e560ecbf82b78ea73f568482dd806e29e7d1027a1905fd4"))
        (300000, uint256("0x1b8d437a34b38b96b8aace5b764fa423d960e6640d11c184dc8215c7596024c8"))
        (400000, uint256("0x5ed5ac1fd6e9ea28e33422141eda939df9b6a3a65c16f56655d6e461039ae56e"))
        (442000, uint256("0xf5eea0a0842db79acd3f434fbf4cb772e13d451aabf4c61f2179faca5ffb8c08"))
        (462000, uint256("0xc0b99dda79dbd220c7845d40636c786d2d5224ab85a86eb7250cb7a7bd7a1c58"))
        (482000, uint256("0x945c1cd0b410cfe51dd04bece6d522bdd94e42f96a2d5861303057724585e9e0"))
        (500000, uint256("0x3ea4bd2c8769e223e33d0842eeb137801d2cbd2d6aa2f412da3116cd1860e098"))
        (522000, uint256("0x889b767099c273d009102c9943b82600a8d052ee791090918b17d400ae1b93de"))
        (530002, uint256("0x7e5982788dae8607994904a59728eff2d69966fa5438e8788ddb1ff931bb4b0a"))
;

static const Checkpoints::CCheckpointData data = {
       &mapCheckpoints,
        1425363097,   // * UNIX timestamp of last checkpoint block
       // 1000000,   // * total number of transactions between genesis and last checkpoint
                    //   (the tx=... number in the SetBestChain debug.log lines)
       // 3000.0    // * estimated number of transactions per day after checkpoint
    };

static Checkpoints::MapCheckpoints mapCheckpointsTestnet;
        //boost::assign::map_list_of
       // ( 546, uint256("0xa0fea99a6897f531600c8ae53367b126824fd6a847b2b2b73817a95b8e27e602"))

static const Checkpoints::CCheckpointData dataTestnet = {
        //&mapCheckpointsTestnet,
       // 1365458829,
        //547,
        //576
    };

static Checkpoints::MapCheckpoints mapCheckpointsRegtest;
        //boost::assign::map_list_of
       // ( 0, uint256("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"))

static const Checkpoints::CCheckpointData dataRegtest = {
        //&mapCheckpointsRegtest,
      //  0,
       // 0,
       // 0
    };

class CMainParams : public CChainParams {
public:
    CMainParams() {
        networkID = CBaseChainParams::MAIN;
        strNetworkID = "main";
        /** 
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 4-byte int at any alignment.
         */
        pchMessageStart[0] = 0xfd;
        pchMessageStart[1] = 0xc0;
        pchMessageStart[2] = 0xb6;
        pchMessageStart[3] = 0xf1;
        vAlertPubKey = ParseHex("04ef014b36647e8433a2cedf76f1d6ea0bc5914ba936fadceda90d7472da3cf442469d3a1ab5ee416e7428726761dd3188bda3d0ae163db491f8ca0bdad92a0506");
        nDefaultPort = 11310;
        bnProofOfWorkLimit = ~uint256(0) >> 20;
        nSubsidyHalvingInterval = 129600;
        nEnforceBlockUpgradeMajority = 750;
        nRejectBlockOutdatedMajority = 950;
        nToCheckBlockUpgradeMajority = 1000;
        nMinerThreads = 0;
        nStakeMinerThreads =0;
        nTargetTimespan = 60 * 60; // 60 Minutes
        nTargetSpacing = 60;   // 60 Seconds
        nStakeTargetSpacing = 2 * 60; // NetCoin: 60 sec
        nCoinbaseMaturity = 10;
        nCoinStakeMaturity = 50;

        const char* pszTimestamp = "Aug 31, 2013: US STOCKS-Wall Street falls, ends worst month since May 2012.";
        CMutableTransaction txNew;
        txNew.vin.resize(1);
        txNew.vout.resize(1);
        txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew.vout[0].nValue = 0 * COIN;
        txNew.vout[0].scriptPubKey = CScript() << ParseHex("0457575678901234567890000222222333444555666777888999000000aaaaabbbbbcccccdddddeeeeeff00ff00ff00ff001234567890abcdef0022446688abc89") << OP_CHECKSIG;
        txNew.nVersion = 2;
        genesis.vtx.push_back(txNew);
        genesis.hashPrevBlock = 0;
        genesis.hashMerkleRoot = genesis.BuildMerkleTree();
        genesis.nVersion = 1;
        genesis.nTime    = 1377903314;
        genesis.nBits = 0x1e0ffff0;
        genesis.nNonce = 12344321;


        hashGenesisBlock = genesis.GetHash();
        assert(hashGenesisBlock == uint256("0x38624e3834cfdc4410a5acbc32f750171aadad9620e6ba6d5c73201c16f7c8d1"));
        assert(genesis.hashMerkleRoot == uint256("0xe5981b72a47998b021ee8995726282d1a575477897d9d5a319167601fffebb21"));

        vSeeds.push_back(CDNSSeedData("netcoinfoundation.org", "dnsseed.netcoinfoundation.org"));

        base58Prefixes[PUBKEY_ADDRESS] = list_of(112);
        base58Prefixes[SCRIPT_ADDRESS] = list_of(5);
        base58Prefixes[SECRET_KEY] =     list_of(240);
        base58Prefixes[EXT_PUBLIC_KEY] = list_of(0x04)(0x88)(0xB2)(0x1E);
        base58Prefixes[EXT_SECRET_KEY] = list_of(0x04)(0x88)(0xAD)(0xE4);

        convertSeed6(vFixedSeeds, pnSeed6_main, ARRAYLEN(pnSeed6_main));

        fRequireRPCPassword = true;
        fMiningRequiresPeers = true;
        fDefaultCheckMemPool = false;
        fAllowMinDifficultyBlocks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fSkipProofOfWorkCheck = false;
        fTestnetToBeDeprecatedFieldRPC = false;
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
        vAlertPubKey = ParseHex("0471dc165db490094d35cde15b1f5d755fa6ad6f2b5ed0f340e3f17f57389c3c2af113a8cbcc885bde73305a553b5640c83021128008ddf882e856336269080496");
        nDefaultPort = 21310;
        nEnforceBlockUpgradeMajority = 51;
        nRejectBlockOutdatedMajority = 75;
        nToCheckBlockUpgradeMajority = 100;
        nMinerThreads = 0;
        nStakeMinerThreads =0;
        nTargetTimespan = 60 * 60; // 60 minutes
        nTargetSpacing = 1 * 60; // 1 minute

        //! Modify the testnet genesis block so the timestamp is valid for a later start.
        genesis.nTime = 1438438055;
        genesis.nNonce = 12345321;
        hashGenesisBlock = genesis.GetHash();
//        assert(hashGenesisBlock == uint256("0x4a1ed64aed30d471b268b7a3ba634d4c63955700db462093a20e3f1f9db6a13f"));

        vFixedSeeds.clear();
        vSeeds.clear();
        vSeeds.push_back(CDNSSeedData("netcoinfoundation.org", "dnsseed.netcoinfoundation.org"));
       // vSeeds.push_back(CDNSSeedData("xurious.com", "testnet-seed.ltc.xurious.com"));
       // vSeeds.push_back(CDNSSeedData("wemine-testnet.com", "dnsseed.wemine-testnet.com"));

        base58Prefixes[PUBKEY_ADDRESS] = list_of(111);
        base58Prefixes[SCRIPT_ADDRESS] = list_of(196);
        base58Prefixes[SECRET_KEY]     = list_of(239);
        base58Prefixes[EXT_PUBLIC_KEY] = list_of(0x04)(0x88)(0xB1)(0x2E);
        base58Prefixes[EXT_SECRET_KEY] = list_of(0x04)(0x88)(0xAD)(0xE2);

        convertSeed6(vFixedSeeds, pnSeed6_test, ARRAYLEN(pnSeed6_test));

        fRequireRPCPassword = true;
        fMiningRequiresPeers = true;
        fDefaultCheckMemPool = false;
        fAllowMinDifficultyBlocks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = true;
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
        nStakeMinerThreads =1;
        nTargetTimespan = 60 * 60; // 3.5 days
        nTargetSpacing = 60; // 2.5 minutes
        bnProofOfWorkLimit = ~uint256(0) >> 1;
        genesis.nTime = 1402442819;
        genesis.nBits = bnProofOfWorkLimit.GetCompact();
        genesis.nNonce = 1261171;
        hashGenesisBlock = genesis.GetHash();
        nDefaultPort = 21310;
//        assert(hashGenesisBlock == uint256("0x530827f38f93b43ed12af0b3ad25a288dc02ed74d6d7857862df51fc56c416f9"));

        vFixedSeeds.clear(); //! Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();  //! Regtest mode doesn't have any DNS seeds.

        fRequireRPCPassword = false;
        fMiningRequiresPeers = false;
        fDefaultCheckMemPool = true;
        fAllowMinDifficultyBlocks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;
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
        fDefaultCheckMemPool = true;
        fAllowMinDifficultyBlocks = false;
        fMineBlocksOnDemand = true;
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
    virtual void setDefaultCheckMemPool(bool afDefaultCheckMemPool)  { fDefaultCheckMemPool=afDefaultCheckMemPool; }
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
