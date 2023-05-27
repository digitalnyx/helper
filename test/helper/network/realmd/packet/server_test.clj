(ns helper.network.realmd.packet.server-test
  (:require
   [clojure.test :refer :all]
   [helper.network.realmd.packet.server :refer :all]
   [gloss.io :as io]
   [helper.utils.conversions :as conv]))

(alter-var-root #'*stack-trace-depth* (constantly 1))

(def encoded-logon-challenge
  [0x00 ;; OPCode
   0x00 ;; Not sure
   0x00 ;; Success
   ;; B
   0xE4 0x49 0x0E 0xA0 0x46 0xD7 0x8E 0x4D 
   0x81 0x0C 0x1E 0xBE 0x3A 0x8F 0x64 0x86 
   0xB0 0x76 0x33 0x50 0xB2 0xFD 0x01 0x00 
   0xC4 0xDA 0x97 0x44 0x6C 0x38 0x9D 0x73
   0x01 ;; g len
   0x07 ;; g
   0x20 ;; N len
   ;; N
   0xB7 0x9B 0x3E 0x2A 0x87 0x82 0x3C 0xAB 
   0x8F 0x5E 0xBF 0xBF 0x8E 0xB1 0x01 0x08 
   0x53 0x50 0x06 0x29 0x8B 0x5B 0xAD 0xBD 
   0x5B 0x53 0xE1 0x89 0x5E 0x64 0x4B 0x89
   ;; s
   0xBB 0xDC 0x0B 0xAE 0xE1 0xE5 0x09 0xC5
   0x96 0xAA 0x86 0xB1 0x51 0xF7 0xDA 0x51 
   0x04 0x47 0x8A 0xD6 0x2F 0x3C 0x4D 0x39 
   0x36 0x85 0x87 0x9F 0xF7 0xB5 0xF6 0xF5
   ;; unk - 16 byte random
   0xED 0x01 0xDF 0xE3 0x58 0xD3 0x7F 0xC4 
   0x85 0xA8 0x84 0xF2 0x20 0x1D 0x65 0x89 
   0x00 ;; security flags
   ])

(def decoded-logon-challenge
  {:opcode :logon-challenge
   :unk-1 0x00
   :errcode :success
   :B 0x739D386C4497DAC40001FDB2503376B086648F3ABE1E0C814D8ED746A00E49E4
   :g 7
   :N 0x894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7
   :s 0xF5F6B5F79F878536394D3C2FD68A470451DAF751B186AA96C509E5E1AE0BDCBB
   :crc 0x89651D20F284A885C47FD358E3DF01ED
   :security-flag 0x00})

(def encoded-logon-challenge-err
  [0x00 ;; OPCode
   0x00 ;; unk-1
   0x04 ;; Err Code
   ])

(def decoded-logon-challenge-err
  {:opcode :logon-challenge
   :unk-1 0x00
   :errcode :unknown-account})

(def encoded-logon-proof
  [0x01 ;; OPCode
   0x00 ;; Err Code
   ;; M2
   0xFC 0xC3 0x8A 0xA1 0x49 0xFF 0x07 0xF2 
   0x8A 0x4F 0xBB 0xDB 0xE1 0x89 0xAE 0x1F 
   0xA1 0xBE 0xB7 0xC8
   ;; unk-1
   0x00 0x00 0x00 0x00
   ])

(def decoded-logon-proof
  {:opcode :logon-proof
   :errcode :success
   :M2 0xC8B7BEA11FAE89E1DBBB4F8AF207FF49A18AC3FC
   :unk-1 0x00000000})

(def encoded-logon-proof-err
  [0x01 ;; OPCode
   0x04 ;; Err Code
   ])

(def decoded-logon-proof-err
  {:opcode :logon-proof
   :errcode :unknown-account})

(def encoded-realm-list
  [0x10 ;; OPCode
   0x2B 0x00 ;; Packet Length
   0x00 0x00 0x00 0x00 ;; unk-1
   0x01 ;; Number of Realms
   ;; Realm 1
   0x01 0x00 0x00 0x00 ;; Type 
   0x00 ;; Flags
   0x4D 0x61 0x4E 0x47 0x4F 0x53 0x00 ;; Name
   ;; Address, : terminated
   0x31 0x39 0x32 0x2E 0x31 0x36 0x38 0x2E 0x30 0x2E 0x33 0x3A
   ;; Port, \0 terminated
   0x38 0x30 0x38 0x35 0x00 
   0x00 0x00 0x00 0x00 ;; Population
   0x00 ;; Characters
   0x01 ;; Timezone
   0x00 ;; unk-1
   ;; End Realm 1
   0x02 0x00 ;; unk-2
   ])

(def decoded-realm-list
  {:opcode :realm-list
   :unk-1 0
   :realms
   [{:type :pvp
     :flags :none
     :name "MaNGOS"
     :address "192.168.0.3"
     :port 8085
     :population 0.0
     :characters 0
     :timezone :development
     :unk-1 0}]
   :unk-2 2})

(def decoded-realm-list-nounk
  {:opcode :realm-list
   :realms
   [{:type :pvp
     :flags :none
     :name "MaNGOS"
     :address "192.168.0.3"
     :port 8085
     :population 0.0
     :characters 0
     :timezone :development}]})

(def decoded-unknown
  {:opcode :unknown})

(def encoded-unknown
  [0xFF ;; OPCode
   0x01 0x02 0x03 0x04 0x05 0x06
   ])

(deftest realmd-server-framing
  
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

  (testing "logon challenge error"

    (is (= encoded-logon-challenge-err
           (conv/heaps->bytes
            (io/encode 
             realmd
             decoded-logon-challenge-err))))

    (is (= decoded-logon-challenge-err
           (io/decode
            realmd
            (conv/into-bb encoded-logon-challenge-err)))))

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

  (testing "logon proof error"

    (is (= encoded-logon-proof-err
           (conv/heaps->bytes
            (io/encode 
             realmd
             decoded-logon-proof-err))))

    (is (= decoded-logon-proof-err
           (io/decode
            realmd
            (conv/into-bb encoded-logon-proof-err)))))

  (testing "realm list"

    (is (= encoded-realm-list
           (conv/heaps->bytes
            (io/encode 
             realmd
             decoded-realm-list))))

    (is (= encoded-realm-list
           (conv/heaps->bytes
            (io/encode 
             realmd
             decoded-realm-list-nounk))))

    (is (= decoded-realm-list
           (io/decode
            realmd
            (conv/into-bb encoded-realm-list)
            false))))

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
