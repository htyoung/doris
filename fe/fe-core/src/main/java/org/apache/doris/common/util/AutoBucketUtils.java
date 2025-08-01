// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package org.apache.doris.common.util;

import org.apache.doris.catalog.DiskInfo;
import org.apache.doris.catalog.DiskInfo.DiskState;
import org.apache.doris.catalog.Env;
import org.apache.doris.common.AnalysisException;
import org.apache.doris.common.Config;
import org.apache.doris.system.Backend;
import org.apache.doris.system.SystemInfoService;

import com.google.common.collect.ImmutableMap;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class AutoBucketUtils {
    private static Logger logger = LogManager.getLogger(AutoBucketUtils.class);

    static final long SIZE_100MB = 100 * 1024 * 1024L;
    static final long SIZE_1GB = 1 * 1024 * 1024 * 1024L;
    static final long SIZE_1TB = 1024 * SIZE_1GB;

    private static int getBENum() {
        SystemInfoService infoService = Env.getCurrentSystemInfo();
        ImmutableMap<Long, Backend> backends;
        try {
            backends = infoService.getAllBackendsByAllCluster();
        } catch (AnalysisException e) {
            logger.warn("failed to get backends with current cluster", e);
            return 0;
        }

        int activeBENum = 0;
        for (Backend backend : backends.values()) {
            if (backend.isAlive()) {
                ++activeBENum;
            }
        }
        return activeBENum;
    }

    private static int getBucketsNumByBEDisks() {
        SystemInfoService infoService = Env.getCurrentSystemInfo();
        ImmutableMap<Long, Backend> backends;
        try {
            backends = infoService.getAllBackendsByAllCluster();
        } catch (AnalysisException e) {
            logger.warn("failed to get backends with current cluster", e);
            return 0;
        }

        int buckets = 0;
        for (Backend backend : backends.values()) {
            if (!backend.isLoadAvailable()) {
                continue;
            }

            ImmutableMap<String, DiskInfo> disks = backend.getDisks();
            for (DiskInfo diskInfo : disks.values()) {
                if (diskInfo.getState() == DiskState.ONLINE && diskInfo.hasPathHash()) {
                    buckets += (int) ((diskInfo.getAvailableCapacityB() - 1) / (50 * SIZE_1GB) + 1);
                }
            }
        }
        return buckets;
    }

    private static int convertPartitionSizeToBucketsNum(long partitionSize) {
        partitionSize /= 5; // for compression 5:1

        // <= 100MB, 1 bucket
        // <= 1GB, 2 buckets
        // > 1GB, round to (size / 1G)
        if (partitionSize <= SIZE_100MB) {
            return 1;
        } else if (partitionSize <= SIZE_1GB) {
            return 2;
        } else {
            int partitionSizePerBucket = Config.autobucket_partition_size_per_bucket_gb;
            if (partitionSizePerBucket <= 0) {
                if (Config.isCloudMode()) {
                    partitionSizePerBucket = 10;
                } else {
                    partitionSizePerBucket = 5;
                }
                logger.debug("autobucket_partition_size_per_bucket_gb <= 0, use adaptive {}",
                        partitionSizePerBucket);
            }
            return  (int) ((partitionSize - 1) / (partitionSizePerBucket * SIZE_1GB) + 1);
        }
    }

    public static int getBucketsNum(long partitionSize) {
        int bucketsNumByPartitionSize = convertPartitionSizeToBucketsNum(partitionSize);
        int bucketsNumByBE = Config.isCloudMode() ? Integer.MAX_VALUE : getBucketsNumByBEDisks();
        int bucketsNum = Math.min(Config.autobucket_max_buckets, Math.min(bucketsNumByPartitionSize, bucketsNumByBE));
        int beNum = getBENum();
        logger.debug("AutoBucketsUtil: bucketsNumByPartitionSize {}, bucketsNumByBE {}, bucketsNum {}, beNum {}",
                bucketsNumByPartitionSize, bucketsNumByBE, bucketsNum, beNum);
        if (bucketsNum < bucketsNumByPartitionSize && bucketsNum < beNum) {
            bucketsNum = beNum;
        }
        bucketsNum = Math.min(bucketsNum, Config.autobucket_max_buckets);
        logger.debug("AutoBucketsUtil: final bucketsNum {}", bucketsNum);
        return bucketsNum;
    }

    public static int getBucketsNum(long partitionSize, int minBuckets) {
        int bucketsNum = getBucketsNum(partitionSize);
        return Math.max(minBuckets, bucketsNum);
    }
}
