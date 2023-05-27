(ns helper.network.realmd.packet.client
  (:require
   [gloss.core :as gloss]
   [gloss.io :as io]
   [clojure.string :refer [upper-case]]
   [helper.utils.shine :as shine]
   [helper.utils.conversions :as conv]
   [taoensso.timbre :as timbre
    :refer [log  trace  debug  info  warn  error  fatal]]))

;; Header opcode is just on ubyte.

(def opcodes
  {:logon-challenge 0x00
   :logon-proof 0x01
   :realm-list 0x10})

(def rev-opcodes
  (clojure.set/map-invert opcodes))

(def header
  (gloss/compile-frame
   (gloss/ordered-map
    :opcode :ubyte)
   (fn [v] (if-let [opcode (get opcodes 
                                (:opcode v))]
             {:opcode opcode}
             {:opcode 0xFF}))
   (fn [v] (if-let [opcode (get rev-opcodes 
                                (:opcode v))]
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

(defmethod realmd-packet :logon-challenge [edn]
  (gloss/compile-frame
   (gloss/ordered-map
    :unk-1 (shine/unk :ubyte 0x03)
    :packet
    (gloss/finite-frame 
     :uint16-le
     (gloss/ordered-map
      :game 
      (gloss/compile-frame 
       (gloss/string :ascii :delimiters [0])
       #(conv/reverse-string %)
       #(conv/reverse-string %))
      :version-major :ubyte
      :version-mid :ubyte
      :version-minor :ubyte
      :build-number :uint16-le
      :arch 
      (gloss/compile-frame 
       (gloss/string :ascii :delimiters [0])
       #(conv/reverse-string %)
       #(conv/reverse-string %))
      :platform 
      (gloss/compile-frame 
       (gloss/string :ascii :delimiters [0])
       #(conv/reverse-string %)
       #(conv/reverse-string %))
      :locale 
      (gloss/compile-frame 
       (gloss/string :ascii :length 4)
       #(conv/reverse-string %)
       #(conv/reverse-string %))
      :time-bias 
      (gloss/compile-frame 
       :int32-le
       #(* 60 %)
       #(/ % 60))
      :client-ip 
      (gloss/compile-frame 
       (gloss/string :ascii :length 4)
       #(conv/ip-string->string %)
       #(conv/string->ip-string %))
      :account-name 
      (gloss/prefix
       [:ubyte (gloss/string :utf8)]
       #(second %)
       (fn [v] [(count v) (upper-case v)]))
      :opcode :logon-challenge)))
   (fn [v] {:unk-1 3 :packet v})
   #(merge {:unk-1 (:unk-1 %)} (:packet %))))

(defmethod realmd-packet :logon-proof [edn]
  (gloss/ordered-map
   :A (shine/openssl-bignum :length 32)
   :M1 (shine/openssl-bignum :length 20)
   :crc (shine/openssl-bignum :length 20)
   :key-count :ubyte
   :security-flags :ubyte
   :opcode :logon-proof))

(defmethod realmd-packet :realm-list [edn]
  (gloss/ordered-map
   :unk-1 (shine/unk :uint32 0)
   :opcode :realm-list))

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



