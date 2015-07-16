// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pos.h>



bnProofOfStakeLimit(~uint256(0) >> 20);

unsigned int ComputeMaxBits(CBigNum bnTargetLimit, unsigned int nBase, int64_t nTime)
{
    // Testnet has min-difficulty blocks
    // after nTargetSpacing*2 time between blocks:
    //if (fTestNet && nTime > TargetSpacing *2)
        //return bnTargetLimit.GetCompact();

    CBigNum bnResult;
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
            if (nTime >= max(pindexBest->GetPastTimeLimit()+1, PastDrift(pindexBest->GetBlockTime())))
            {
                // Pandacoin: since I've had to get rid of CTransaction's nTime,
                // it's no longer possible to alter the nTime to fit the past block drift
                nTime = nTxTime;

                vtx.insert(vtx.begin() + 1, txCoinStake);
                hashMerkleRoot = BuildMerkleTree();

                // append a signature to our block
                return key.Sign(GetHash(), vchBlockSig);
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
bool CTransaction::GetCoinAge(CTxDB& txdb, unsigned int nTxTime, uint64_t& nCoinAge, int64_t& nCoinValue) const
{
    CBigNum bnCentSecond = 0;  // coin age in the unit of cent-seconds
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
           bnCentSecond += CBigNum(nValueIn) * nDilatedAge / CENT;
        else
           bnCentSecond += CBigNum(nValueIn) * (nTxTime-nPrevTime) / CENT;

        if (fDebug && GetBoolArg("-printcoinage"))
            printf("coin age nValueIn=%"PRI64d" nTimeDiff=%d bnCentSecond=%s\n", nValueIn, nTxTime - nPrevTime, bnCentSecond.ToString().c_str());
    }

    CBigNum bnCoinDay = bnCentSecond * CENT / COIN / (24 * 60 * 60);
    if (fDebug && GetBoolArg("-printcoinage"))
        printf("coin age bnCoinDay=%s\n", bnCoinDay.ToString().c_str());
    nCoinAge = bnCoinDay.getuint64();
    return true;
}

// ppcoin: total coin age spent in block, in the unit of coin-days.
bool CBlock::GetCoinAge(uint64_t& nCoinAge) const
{
    nCoinAge = 0;

    CTxDB txdb("r");
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

