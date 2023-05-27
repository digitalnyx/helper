(ns helper.network.realmd.packet.client-test
  (:require
   [clojure.test :refer :all]
   [helper.network.realmd.packet.client :refer :all]
   [gloss.io :as io]
   [helper.utils.conversions :as conv]
   [helper.utils.shine :as shine]))

;(set! *stack-trace-depth* 1)
(alter-var-root #'*stack-trace-depth* (constantly 1))

(def encoded-logon-challenge
  [0x00 ;; OPCode
   0x03 ;; unk-1
   0x28 0x00 ;; Packet Length
   0x57 0x6F 0x57 0x00 ;; WoW
   0x01 ;; Version Major
   0x0C ;; Version Mid
   0x01 ;; Version Minor
   0xF3 0x16 ;; Build Number
   0x36 0x38 0x78 0x00 ;; x86
   0x58 0x53 0x4F 0x00 ;; OSX
   0x53 0x55 0x6E 0x65 ;; enUS
   0x98 0xFE 0xFF 0xFF ;; Time Bias
   0x7F 0x00 0x00 0x01 ;; IP
   0x0A ;; Acct Length
   ;; HOSEHEAD10
   0x48 0x4F 0x53 0x45 0x48 0x45 0x41 0x44 0x31 0x30
   ])

(def decoded-logon-challenge
  {:opcode :logon-challenge
   :unk-1 3
   :game "WoW"
   :version-major 1
   :version-mid 12
   :version-minor 1
   :build-number 5875
   :arch "x86"
   :platform "OSX"
   :locale "enUS"
   :time-bias -6
   :client-ip "127.0.0.1"
   :account-name "HOSEHEAD10"})

(def encoded-logon-proof
  [0x01 ;; OPCode 
   ;; A Value
   0x3A 0xCF 0xD7 0xBA 0x8F 0xA9 0x3C 0xBA
   0x68 0x83 0x0F 0xF8 0xBA 0x26 0x9C 0x0C 
   0x02 0x19 0xE4 0xCE 0xF9 0xE3 0xEC 0xA6 
   0x99 0xEA 0xFF 0x8D 0x99 0xEA 0x63 0x3A 
   ;; M1 Value
   0x80 0x7B 0x37 0x91 0xEB 0xE6 0x7D 0xDB 0xD0 0x13 
   0x95 0xCC 0xDF 0x15 0xDF 0x97 0x7B 0x98 0x22 0x30 
   ;; CRC Value
   0x53 0xF6 0x02 0xCB 0xCB 0x9D 0xFA 0x2A 0xB9 0x48 
   0x85 0xAF 0x9A 0xBE 0xFB 0x00 0x0D 0x0F 0x0A 0x07 
   0x00 ;; Key Count 
   0x00 ;; Security Flags
   ])

(def decoded-logon-proof
  {:opcode :logon-proof
   :A 0x3A63EA998DFFEA99A6ECE3F9CEE419020C9C26BAF80F8368BA3CA98FBAD7CF3A
   :M1 0x3022987B97DF15DFCC9513D0DB7DE6EB91377B80
   :crc 0x70A0F0D00FBBE9AAF8548B92AFA9DCBCB02F653
   :key-count 0
   :security-flags 0})

(def encoded-realm-list
  [0x10 ;; OPCode
   0x00 0x00 0x00 0x00 ;; Filler
   ])

(def decoded-realm-list
  {:opcode :realm-list
   :unk-1 0})

(def decoded-unknown
  {:opcode :unknown})

(def encoded-unknown
  [0xFF ;; OPCode
   0x01 0x02 0x03 0x04 0x05 0x06
   ])

(deftest realmd-client-framing
  
  (testing "logon challenge"

    (is (= encoded-logon-challenge
           (conv/heaps->bytes
            (io/encode 
             realmd
             decoded-logon-challenge))))

    (is (= decoded-logon-challenge
           (io/decode
            realmd
            (conv/into-bb encoded-logon-challenge)))))

  (testing "logon proof"

    (is (= encoded-logon-proof
           (conv/heaps->bytes
            (io/encode 
             realmd
             decoded-logon-proof))))

    (is (= decoded-logon-proof
           (io/decode
            realmd
            (conv/into-bb encoded-logon-proof)))))

  (testing "realm list"

    (is (= encoded-realm-list
           (conv/heaps->bytes
            (io/encode 
             realmd
             decoded-realm-list))))

    (is (= decoded-realm-list
           (io/decode
            realmd
            (conv/into-bb encoded-realm-list)))))

  (testing "unknown"

    (is (= '()
           (conv/heaps->bytes
            (io/encode 
             realmd
             decoded-unknown))))

    (is (= {:body [1 2 3 4 5 6]
            :header "0xFF"
            :opcode :unknown-decode}
           (io/decode
            realmd
            (conv/into-bb encoded-unknown))))))


