// Copyright (c) 2009-2015 The Netcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef POS_H
#define POS_H

//#include "chain.h"
#include "chainparams.h"
//#include "timedata.h"
//#include "util.h"
//#include "main.h"


extern unsigned int nStakeMinAge;
extern unsigned int nStakeMaxAge;
extern int64_t nLastCoinStakeSearchInterval;



inline int64_t PastDrift(int64_t nTime)   { return nTime - 10 * 60; } // up to 10 minutes from the past
inline int64_t FutureDrift(int64_t nTime) { return nTime + 10 * 60; } // up to 10 minutes from the future

int64_t GetProofOfStakeReward(int64_t nCoinAge, int64_t nCoinValue, int64_t nFees, int64_t nHeight);
int64_t GetPIRRewardCoinYear(int64_t nCoinValue, int64_t nHeight);


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
        return Params().ProofOfStakeLimit();
}



#endif // POS_H
