(ns helper.network.world.packet.server-test
  (:require
   [clojure.test :refer :all]
   [helper.network.world.packet.server :refer :all]
   [gloss.io :as io]
   [helper.utils.conversions :as conv]))

(def encoded-auth-challenge
  [0x00 0x06 0xEC 0x01 0x97 0x58 0xDD 0x53])

(def encoded-auth-challenge-1
  [0 38 236 1 0x97 0x58 0xDD 0x53 233 107 59 220 
   16 107 8 138 172 240 126 17 102 156 120 
   188 161 136 64 159 24 34 35 6 138 139 67 
   41 71 95 37 142])

(def decoded-auth-challenge
  {:opcode :auth-challenge
   :server-seed (BigInteger. "53DD5897" 16)
   :unk-1 nil})

(def encoded-enum-char
  [0x00 0xA6 ;; Packet Length
   0x3B 0x00 ;; OPCode
   0x01 ;; Error
   ;; GUID
   0x01 0x00 0x00 0x00 0x00 0x00 0x00 0x00 
   ;; I (Account Name in Caps)
   0x42 0x6C 0x61 0x68 0x00 
   0x07 ;; Race
   0x01 ;; Class
   0x01 ;; Gender
   0x03 ;; Skin
   0x00 ;; Face
   0x06 ;; Hair Style
   0x04 ;; Hair Color
   0x02 ;; Facial Hair
   0x01 ;; Level
   0x01 0x00 0x00 0x00 ;; Zone
   0x00 0x00 0x00 0x00 ;; Map
   0xE1 0x6A 0xC2 0xC5 ;; X
   0xF2 0xB2 0xA5 0x43 ;; Y
   0x3D 0x9A 0xBF 0x43 ;; Z
   0x00 0x00 0x00 0x00 ;; Guild ID
   0x00 0x00 0x00 0x00 ;; Char Flags
   0x00 ;; First Login
   0x00 0x00 0x00 0x00 ;; Pet Display ID
   0x00 0x00 0x00 0x00 ;; Pet Level
   0x00 0x00 0x00 0x00 ;; Pet Family

   ;; Inventory Slots
   0x00 0x00 0x00 0x00 0x00 
   0x00 0x00 0x00 0x00 0x00 
   0x00 0x00 0x00 0x00 0x00 
   0xA3 0x26 0x00 0x00 0x04 
   0x00 0x00 0x00 0x00 0x00 
   0x00 0x00 0x00 0x00 0x00 
   0xA4 0x26 0x00 0x00 0x07 
   0x9D 0x27 0x00 0x00 0x08 
   0x00 0x00 0x00 0x00 0x00 
   0x00 0x00 0x00 0x00 0x00 
   0x00 0x00 0x00 0x00 0x00 
   0x00 0x00 0x00 0x00 0x00 
   0x00 0x00 0x00 0x00 0x00 
   0x00 0x00 0x00 0x00 0x00 
   0x00 0x00 0x00 0x00 0x00 
   0x06 0x06 0x00 0x00 0x15 
   0x2A 0x49 0x00 0x00 0x0E 
   0x00 0x00 0x00 0x00 0x00 
   0x00 0x00 0x00 0x00 0x00 
   0x00 0x00 0x00 0x00 0x00 
   ])

(deftest world-server-framing
  
  (testing "auth challenge"

    (is (= encoded-auth-challenge
           (conv/heaps->bytes
            (encode 
             decoded-auth-challenge))))

    (is (= decoded-auth-challenge
           (decode
            (conv/into-bb 
             encoded-auth-challenge))))

    (is (= decoded-auth-challenge
           (decode
            (conv/into-bb 
             encoded-auth-challenge-1)))))

  (testing "char enumeration"

    (is (= {}
           (decode
            (conv/into-bb
             encoded-enum-char)))))
)
