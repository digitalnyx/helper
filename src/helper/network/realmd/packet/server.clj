(ns helper.network.realmd.packet.server
  (:require
   [gloss.core :as gloss]
   [gloss.io :as io]
   [clojure.string :refer [upper-case]]
   [helper.utils.shine :as shine]
   [helper.utils.conversions :as conv]
   [taoensso.timbre :as timbre
    :refer [log  trace  debug  info  warn  error  fatal]]))

;; Headers are not uniform, made use of sub headers.

;; Lookup ubyte by opcode
(def opcodes
  {:logon-challenge 0x00
   :logon-proof 0x01
   :realm-list 0x10})

;; Lookup opcode by ubyte
(def rev-opcodes
  (clojure.set/map-invert opcodes))

;; Appear to be shared...
(def errcodes
  (gloss/enum 
   :ubyte 
   {:success 0x00 
    :err-1 0x01
    :err-2 0x02
    :banned 0x03
    :unknown-account 0x04
    :incorrect-password 0x05
    :already-online 0x06}))

(def header
  (gloss/compile-frame
   (gloss/ordered-map
    :opcode :ubyte)
   (fn [v] 
     (if-let [opcode (get opcodes (:opcode v))]
       {:opcode opcode}
       {:opcode 0xFF}))
   (fn [v] 
     (if-let [opcode (get rev-opcodes (:opcode v))]
       {:opcode opcode}
       {:opcode-val (:opcode v)}))))

(defmulti realmd-packet
  (fn [v] 
    ;;(println "Dispatch Val:" (:opcode v))
    (:opcode v)))

(gloss/defcodec realmd
  (shine/header+
   header

   (fn [header]
      ;;(println "Header->Body:" header)
      (realmd-packet 
       (assoc header :opcode
              (:opcode header :unknown-decode))))

   (fn [body] 
     ;;(println "Body->Header:" body)
     (if (get opcodes (:opcode body))
       body
       (assoc body 
         :opcode :unknown-encode
         :header (:opcode body)
         :body (dissoc body :opcode))))))

(def logon-challenge
  (gloss/ordered-map
   :B (shine/openssl-bignum :length 32)
   :g (shine/openssl-bignum :prefix :ubyte)
   :N (shine/openssl-bignum :prefix :ubyte)
   :s (shine/openssl-bignum :length 32)
   :crc (shine/openssl-bignum :length 16)
   :security-flag :ubyte
   :opcode :logon-challenge
   :errcode :success))

(def logon-challenge-subheader
  (gloss/header
    errcodes
    ;; SubHeader->Body
    (fn [v] 
      ;;(println "SubHeader->Body:" v)
      (if (= :success v)
        ;; Success Body
        logon-challenge
        ;; Error Body, just the error code
        (gloss/ordered-map 
         :errcode v
         :opcode :logon-challenge)))
    ;; Body->SubHeader
    (fn [v]
      ;;(println "Body->SubHeader:" v)
      (:errcode v))))

(defmethod realmd-packet :logon-challenge [edn]
  (gloss/compile-frame
   (gloss/ordered-map
    :unk-1 (shine/unk :ubyte 0)
    :subheader logon-challenge-subheader)
   ;; Encode SubHeader
   (fn [v] {:unk-1 0 :subheader v})
   ;; Decode SubHeader
   (fn [v] 
     ;;(println "Decoding: " v)
     (merge 
      (dissoc v :subheader)
      (:subheader v)))))

(def logon-proof
  (gloss/ordered-map
   :M2 (shine/openssl-bignum :length 20)
   :unk-1 (shine/unk :uint32 0)
   :opcode :logon-proof
   :errcode :success))

(defmethod realmd-packet :logon-proof [edn]
  (gloss/header
    errcodes
    ;; SubHeader->Body
    (fn [v] 
      ;;(println "SubHeader->Body:" v)
      (if (= :success v)
        ;; Success Body
        logon-proof
        ;; Error Body, just the error code
        (gloss/ordered-map 
         :errcode v
         :opcode :logon-proof)))
    ;; Body->SubHeader
    (fn [v]
      ;;(println "Body->SubHeader:" v)
      (:errcode v))))

(comment
 (gloss/defcodec realm
   (gloss/ordered-map
    :type :uint32-le
    :flags :ubyte
    :name (gloss/string :ascii :delimiters [0])
    :address (gloss/string :ascii :delimiters [0])
    :popultaion :float32-le
    :characters :ubyte
    :timezone :ubyte
    :unk-1 :ubyte
    )))

(defmethod realmd-packet :realm-list [edn]
  (gloss/finite-frame
   :uint16-le
   (gloss/ordered-map
    :unk-1 (shine/unk :uint32-le 0)
    :realms 
    (gloss/repeated 
     (gloss/ordered-map
      :type 
      (gloss/enum 
       :uint32-le
       {:normal 0x00 
        :pvp 0x01
        :normal-1 0x04
        :rp 0x06
        :rp-pvp 0x08})
      :flags 
      (gloss/enum 
       :ubyte 
       {:none 0x00 
        :invalid 0x01
        :offline 0x02
        :specify-build 0x04
        :unk-1 0x08
        :unk-2 0x10
        :new-players 0x20
        :recommended 0x40
        :full 0x80})
      :name (gloss/string :ascii :delimiters [0])
      :address (gloss/string :ascii :delimiters [":"])
      :port 
      (gloss/compile-frame
       (gloss/string :ascii :delimiters [0])
       #(str %)
       #(Integer/parseInt %))
      ;; The formula to calculate the value in this field is: 
      ;; playerCount / maxPlayerCount * 2. 
      :population :float32-le
      :characters :ubyte
      :timezone 
      (gloss/enum 
       :ubyte 
       {:development 1
        :united-states 2 
        :oceanic 3
        :latin-america 4
        :tournament 5
        :korea 6
        :tournament-1 7
        :english 8
        :german 9
        :french 10
        :spanish 11
        :russian 12
        :tournament-2 13
        :taiwan 14
        :tournament-3 15
        :china 16
        :cn-1 17
        :cn-2 18
        :cn-3 19
        :cn-4 20
        :cn-5 21
        :cn-6 22
        :cn-7 23
        :cn-8 24
        :tournament-4 25
        :test-server 26
        :tournament-5 27
        :qa-server 28
        :cn-9 29})
      :unk-1 (shine/unk :ubyte 0))
     :prefix :ubyte)
    :unk-2 (shine/unk :uint16-le 2)
    :opcode :realm-list)))

;; Default for Decoding
(defmethod realmd-packet :unknown-decode [edn]
 (warn "Unknown Realmd Client Decode.")
 (gloss/compile-frame 
  (gloss/ordered-map
   :body (gloss/repeated :ubyte :prefix :none)
   :header (format "0x%X" (:opcode-val edn))
   :opcode :unknown-decode)))

(defmethod realmd-packet :unknown-encode [edn]
  (warn "Unknown Realmd Client Encode.")
  nil)
