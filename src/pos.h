// Copyright (c) 2009-2014 The Netcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef POS_H
#define POS_H

#include <test/bignum.h>
#include "chain.h"
#include "chainparams.h"
#include "timedata.h"

class CWallet;

void StakeMiner(CWallet *pwallet);

// Netcoin PIR personal staking interest rate is organised into percentage reward bands based on the value of the coins being staked
// madprofezzor@gmail.com

static const int PIR_LEVELS = 6; // number of entries in PIR_THRESHOLDS
static const int PIR_PHASES = 3;
static const int64_t PIR_PHASEBLOCKS = 365 * 24 * 60; // one year for each phase

static const int64_t PIR_THRESHOLDS[PIR_LEVELS] = {
    0,
    1000,
    10000,
    100000,
    1000000,
    10000000
}; // unit is netcoins.  Must start with 0

static const int64_t PIR_RATES[PIR_PHASES][PIR_LEVELS] = {
        {10,15,20,30,80,100},   // Year 1
        {20,25,30,35,40,45 },   // Year 2
        {20,22,24,26,28,30 }    // Year 3+
};

// netcoin Coin Age uses a diminishing returns rule to encourage and reward frequent staking attempts
static const int COINAGE_TIME_DILATION_HALFLIFE_DAYS = 90;
static const int COINAGE_FULL_REWARD_DAYS = 30;

unsigned int ComputeMinWork(unsigned int nBase, int64_t nTime);
unsigned int ComputeMinStake(unsigned int nBase, int64_t nTime, unsigned int nBlockTime);

// select stake target limit according to hard-coded conditions
uint256 inline GetProofOfStakeLimit(int nHeight, unsigned int nTime)
{
        return bnProofOfStakeLimit;
}

int64_t GetPastTimeLimit() const
{
    return GetMedianTimePast();
}

// entropy bit for stake modifier if chosen by modifier
unsigned int GetStakeEntropyBit() const
{
    // Take last bit of block hash as entropy bit
    unsigned int nEntropyBit = ((GetHash().Get64()) & 1llu);
    if (fDebug && GetBoolArg("-printstakemodifier"))
        printf("GetStakeEntropyBit: hashBlock=%s nEntropyBit=%u\n", GetHash().ToString().c_str(), nEntropyBit);
    return nEntropyBit;
}

// ppcoin: two types of block: proof-of-work or proof-of-stake
bool IsProofOfStake() const
{
    return (vtx.size() > 1 && vtx[1].IsCoinStake());
}

bool IsProofOfWork() const
{
    return !IsProofOfStake();
}

std::pair<COutPoint, unsigned int> GetProofOfStake() const
{
    return IsProofOfStake()? std::make_pair(vtx[1].vin[0].prevout, nTime) : std::make_pair(COutPoint(), (unsigned int)0);
}

#endif // POS_H
