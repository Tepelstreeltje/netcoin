// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chain.h"

using namespace std;

/**
 * CChain implementation
 */
void CChain::SetTip(CBlockIndex *pindex, bool fProofOfStake) {
    if (pindex == NULL) {
        vChain.clear();
        return;
    }
    vChain.resize(pindex->nHeight + 1);
    while (pindex && vChain[pindex->nHeight] && (pindex->IsProofOfStake() != fProofOfStake)) {
        vChain[pindex->nHeight] = pindex;
        pindex = pindex->pprev;
    }
}

CBlockLocator CChain::GetLocator(const CBlockIndex *pindex) const {
    int nStep = 1;
    std::vector<uint256> vHave;
    vHave.reserve(32);

    if (!pindex)
        pindex = Tip();
    while (pindex) {
        vHave.push_back(pindex->GetBlockHash());
        // Stop when we have added the genesis block.
        if (pindex->nHeight == 0)
            break;
        // Exponentially larger steps back, plus the genesis block.
        int nHeight = std::max(pindex->nHeight - nStep, 0);
        if (Contains(pindex)) {
            // Use O(1) CChain index if possible.
            pindex = (*this)[nHeight];
        } else {
            // Otherwise, use O(log n) skiplist.
            pindex = pindex->GetAncestor(nHeight);
        }
        if (vHave.size() > 10)
            nStep *= 2;
    }

    return CBlockLocator(vHave);
}

const CBlockIndex *CChain::FindFork(const CBlockIndex *pindex) const {
    if (pindex->nHeight > Height())
        pindex = pindex->GetAncestor(Height());
    while (pindex && !Contains(pindex))
        pindex = pindex->pprev;
    return pindex;
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

LogPrintf("GetCoinAge::%s\n", ToString().c_str());

    if (IsCoinBase())
        return true;

    BOOST_FOREACH(const CTxIn& txin, vin)
    {
        // First try finding the previous transaction in database
        CBlockUndo txPrev;
        CDiskTxPos pos;
        if (!txPrev.ReadFromDisk(pos.nPos, pindexBestHeader->GetBlockHash()))
            continue;  // previous transaction not in main chain

        //Helpzzz ReadFromDisk
        // Read block header
        CBlockIndex block;
        if (!ReadFromDisk(block.nFile, block.nDataPos, false))
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
    nCoinAge = bnCoinDay;
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
