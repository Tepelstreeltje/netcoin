// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pos.h>
#include "chain.h"
#include "chainparams.h"
#include "timedata.h"
#include "wallet.h"
#include "main.h"
#include "ecwrapper.h"

unsigned int nStakeMinAge = 1 * 60 * 60; // 1 hour
unsigned int nStakeMaxAge = 2592000; // 30 days

bnProofOfStakeLimit(~uint256(0) >> 20);

// Netcoin: PERSONALISED INTEREST RATE CALCULATION
// madprofezzor@gmail.com

// returns an integer between 0 and PIR_PHASES-1 representing which PIR phase the supplied block height falls into
int GetPIRRewardPhase(int64_t nHeight)
{
   int64_t Phase0StartHeight = (!fTestNet ? BLOCK_HEIGHT_POS_AND_DIGISHIELD_START : BLOCK_HEIGHT_POS_AND_DIGISHIELD_START_TESTNET);
   int phase = (int)( (nHeight-Phase0StartHeight) / PIR_PHASEBLOCKS);
   return min(PIR_PHASES-1, max(0,phase) );
}

int64_t GetPIRRewardCoinYear(int64_t nCoinValue, int64_t nHeight)
{
    // work out which phase rates we should use, based on the block height
    int nPhase = GetPIRRewardPhase(nHeight);

    // find the % band that contains the staked value
    if (nCoinValue >= PIR_THRESHOLDS[PIR_LEVELS-1] * COIN)
        return PIR_RATES[nPhase][PIR_LEVELS-1]  * CENT;

    int nLevel = 0;
    for (int i = 1; i<PIR_LEVELS; i++)
    {
        if (nCoinValue < PIR_THRESHOLDS[i] * COIN)
        {
                nLevel = i-1;
                break;
        };
    };


    // interpolate the PIR for this staked value
    // a simple way to interpolate this using integer math is to break the range into 100 slices and find the slice where our coin value lies
    // Rates and Thresholds are integers, CENT and COIN are multiples of 100, so using 100 slices does not introduce any integer math rounding errors


    int64_t nLevelRatePerSlice = (( PIR_RATES[nPhase][nLevel+1] - PIR_RATES[nPhase][nLevel] ) * CENT )  / 100;
    int64_t nLevelValuePerSlice = (( PIR_THRESHOLDS[nLevel+1] - PIR_THRESHOLDS[nLevel] ) * COIN ) / 100;

    int64_t nTestValue = PIR_THRESHOLDS[nLevel] * COIN;

    int64_t nRewardCoinYear = PIR_RATES[nPhase][nLevel] * CENT;
    while (nTestValue < nCoinValue)
    {
        nTestValue += nLevelValuePerSlice;
        nRewardCoinYear += nLevelRatePerSlice;
    };

    return nRewardCoinYear;

}

int64_t GetProofOfStakeReward(int64_t nCoinAge, int64_t nCoinValue,  int64_t nFees, int64_t nHeight)
{

    int64_t nRewardCoinYear = GetPIRRewardCoinYear(nCoinValue, nHeight);

    int64_t nSubsidy = nCoinAge * nRewardCoinYear * 33 / (365 * 33 + 8); //integer equivalent of nCoinAge * nRewardCoinYear / 365.2424242..

    if (fDebug && GetBoolArg("-printcreation"))
        printf("GetProofOfStakeReward(): PIR=%.1f create=%s nCoinAge=%"PRI64d" nCoinValue=%s nFees=%"PRI64d"\n", (double)nRewardCoinYear/(double)CENT, FormatMoney(nSubsidy).c_str(), nCoinAge, FormatMoney(nCoinValue).c_str(), nFees);

    return nSubsidy + nFees;
}

unsigned int ComputeMaxBits(uint256 bnTargetLimit, unsigned int nBase, int64_t nTime)
{
    // Testnet has min-difficulty blocks
    // after nTargetSpacing*2 time between blocks:
    //if (fTestNet && nTime > TargetSpacing *2)
        //return bnTargetLimit.GetCompact();

    uint256 bnResult;
    bnResult.SetCompact(nBase);
    while (nTime > 0 && bnResult < bnTargetLimit)
    {
        // Maximum 400% adjustment...
        bnResult *= 4;
        // ... in best-case exactly 4-times-normal target time
        nTime -= Params().TargetTimespan*4;
    }
    if (bnResult > bnTargetLimit)
        bnResult = bnTargetLimit;
    return bnResult.GetCompact();
}

// minimum amount of stake that could possibly be required nTime after
// minimum proof-of-stake required was nBase
//
unsigned int ComputeMinStake(unsigned int nBase, int64_t nTime, unsigned int nBlockTime)
{
    return ComputeMaxBits(bnProofOfStakeLimit, nBase, nTime);
}

// attempt to generate suitable proof-of-stake
bool CBlock::SignBlock(CWallet& wallet, int64_t nFees)
{
    // if we are trying to sign
    //    something except proof-of-stake block template
    if (!vtx[0].vout[0].IsEmpty())
        return false;

    // if we are trying to sign
    //    a complete proof-of-stake block
    if (IsProofOfStake())
        return true;

    static int64_t nLastCoinStakeSearchTime = GetAdjustedTime(); // startup timestamp

    CKey key;
    CTransaction txCoinStake;
    int64_t nSearchTime = nTime; // search to current time
    unsigned int nTxTime = nTime;

    if (nSearchTime > nLastCoinStakeSearchTime)
    {
        if (wallet.CreateCoinStake(wallet, nBits, nSearchTime-nLastCoinStakeSearchTime, nFees, txCoinStake, nTxTime, key))
        {
            if (nTime >= max(pindexBestHeader->GetPastTimeLimit()+1, PastDrift(pindexBest->GetBlockTime())))
            {block.
                // Pandacoin: since I've had to get rid of CTransaction's nTime,
                // it's no longer possible to alter the nTime to fit the past block drift
                nTime = nTxTime;

                vtx.insert(vtx.begin() + 1, txCoinStake);
                hashMerkleRoot = BuildMerkleTree();

                // append a signature to our block
                return key.Sign(GetHash(), pindexBestHeader->vchBlockSig);
            }
        }
        nLastCoinStakeSearchInterval = nSearchTime - nLastCoinStakeSearchTime;
        nLastCoinStakeSearchTime = nSearchTime;
    }

    return false;
}



//netcoin - fresh coins age faster than older coins
// madprofezzor@gmail.com (who)
// this should encourage and reward users who attempt to maintain full nodes
// and increase the overall network security
// Coin Age is subjected to the following Time-Dilation function to make this happen
//
static const double timeDilationCoeff = 0.693147180559945309417/((double)COINAGE_TIME_DILATION_HALFLIFE_DAYS * 24.0 * 60.0 * 60.0);
static const uint64 secondsAtFullReward = ((uint64)COINAGE_FULL_REWARD_DAYS * 24 * 60 * 60);

bool ApplyTimeDilation(uint64 timeReceived, uint64 timeStaked, uint64& nDilatedCoinAge){
    nDilatedCoinAge = 0;
    uint64 timeDilationStarts = timeReceived + secondsAtFullReward;
    if (timeStaked > timeDilationStarts)
    {
        nDilatedCoinAge = secondsAtFullReward +
                (uint64)((1.0 / timeDilationCoeff) * (1.0 - exp(-timeDilationCoeff * (double)(timeStaked - timeDilationStarts))));

        if (fDebug && GetBoolArg("-printcoinage"))
            printf("staked coins are %.3f days old. POS reward reduces by %.3f percent",
                   (double)(timeStaked-timeReceived)/(24.0*60.0*60.0),
                   100.0 - (double)(nDilatedCoinAge * 100.0) / (double)(timeStaked-timeReceived)
                   );

        // sanity check. Dilation should produce a positive value <= the elapsed time between receiving and staking
        nDilatedCoinAge = max(min(nDilatedCoinAge, timeStaked-timeReceived),(uint64)0);
        return true;
    }
    else
    {
        if (fDebug && GetBoolArg("-printcoinage"))
            printf("staked coins are younger than live wallet reward target. full coinage applies to reward");

        nDilatedCoinAge = max((timeStaked-timeReceived),(uint64)0);
        return false;
    }

}


// ppcoin: total coin age spent in transaction, in the unit of coin-days.
// Only those coins meeting minimum age requirement counts. As those
// transactions not in main chain are not currently indexed so we
// might not find out about their coin age. Older transactions are
// guaranteed to be in main chain by sync-checkpoint. This rule is
// introduced to help nodes establish a consistent view of the coin
// age (trust score) of competing branches.
bool CTransaction::GetCoinAge(CBlockTreeDB& txdb, unsigned int nTxTime, uint64_t& nCoinAge, int64_t& nCoinValue) const
{
    uint256 bnCentSecond = 0;  // coin age in the unit of cent-seconds
    nCoinAge = 0;
    nCoinValue = 0;

printf("GetCoinAge::%s\n", ToString().c_str());

    if (IsCoinBase())
        return true;

    BOOST_FOREACH(const CTxIn& txin, vin)
    {
        // First try finding the previous transaction in database
        CTransaction txPrev;
        CTxIndex txindex;
        if (!txPrev.ReadFromDisk(txdb, txin.prevout, txindex))
            continue;  // previous transaction not in main chain

        // Read block header
        CBlock block;
        if (!block.ReadFromDisk(txindex.pos.nFile, txindex.pos.nBlockPos, false))
            return false; // unable to read block of previous transaction

        unsigned int nPrevTime = block.GetBlockTime();
        if (nPrevTime + nStakeMinAge > nTxTime || nTxTime < nPrevTime)
            continue; // only count coins meeting min age requirement

        int64_t nValueIn = txPrev.vout[txin.prevout.n].nValue;
        nCoinValue += nValueIn;

        uint64 nDilatedAge;
        if (ApplyTimeDilation(nPrevTime, nTxTime, nDilatedAge))
           bnCentSecond += uint256(nValueIn) * nDilatedAge / CENT;
        else
           bnCentSecond += uint256(nValueIn) * (nTxTime-nPrevTime) / CENT;

        if (fDebug && GetBoolArg("-printcoinage"))
            printf("coin age nValueIn=%"PRI64d" nTimeDiff=%d bnCentSecond=%s\n", nValueIn, nTxTime - nPrevTime, bnCentSecond.ToString().c_str());
    }

    uint256 bnCoinDay = bnCentSecond * CENT / COIN / (24 * 60 * 60);
    if (fDebug && GetBoolArg("-printcoinage"))
        printf("coin age bnCoinDay=%s\n", bnCoinDay.ToString().c_str());
    nCoinAge = bnCoinDay.getuint64();
    return true;
}

// ppcoin: total coin age spent in block, in the unit of coin-days.
bool CBlock::GetCoinAge(uint64_t& nCoinAge) const
{
    nCoinAge = 0;

    CBlockTreeDB txdb("r");
    BOOST_FOREACH(const CTransaction& tx, vtx)
    {
        uint64_t nTxCoinAge;
        int64_t nCoinValue;
        if (tx.GetCoinAge(txdb, nTime, nTxCoinAge, nCoinValue))
            nCoinAge += nTxCoinAge;
        else
            return false;
    }

    if (nCoinAge == 0) // block coin age minimum 1 coin-day
        nCoinAge = 1;
    if (fDebug && GetBoolArg("-printcoinage"))
        printf("block coin age total nCoinDays=%"PRI64d"\n", nCoinAge);
    return true;
}

