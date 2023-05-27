(ns helper.network.world.packet.client
  (:require
   [gloss.core :as gloss]
   [gloss.io :as io]
   [helper.utils.shine :as shine]
   [helper.network.world.packet.codecs.player
    :refer [wow-guid]]
   [taoensso.timbre :as timbre
    :refer [log  trace  debug  info  warn  error  fatal]]))

(def opcodes
  {:char-enum 0x037
   :char-login 0x003D
   :auth-session 0x01ED})

(def rev-opcodes
  (clojure.set/map-invert opcodes))

;; Swap upper and lower 2 bytes and subtract
;; 2 from the packet length
(gloss/defcodec real-header
  (gloss/ordered-map
   :packet-length :uint16-be
   :opcode :uint32-le
   :body (gloss/repeated :ubyte :prefix :none)))

(gloss/defcodec better-header
  (gloss/ordered-map
   :opcode :uint32-le
   :packet-length :uint16-be
   :body (gloss/repeated :ubyte :prefix :none)))

(defn into-better-header
  ;; Convert incoming bytes to a more user friendly
  [bytes]
  (let [in (io/decode real-header bytes)]
   (io/encode better-header
              {:opcode (:opcode in)
               :packet-length (- (:packet-length in) 4)
               :body (:body in)})))

(defn into-real-header
  ;; Return outgoing bytes to the real header format
  [bytes]
  (let [out (io/decode better-header bytes)]
    (io/encode real-header
               {:opcode (:opcode out)
                :packet-length (+ (:packet-length out) 4)
                :body (:body out)})))

(def header
   (gloss/compile-frame
    (gloss/ordered-map
     :opcode :uint32-le)
    (fn [v] 
      ;;(debug "Header Encode:" v)
      (if-let [opcode (get opcodes (:opcode v))]
        {:opcode opcode}
        {:opcode 0xFFFFFFFF}))
    (fn [v] 
      ;;(debug "Header Decode:" v)
      (if-let [opcode (get rev-opcodes (:opcode v))]
        {:opcode opcode}
        {:opcode-val (:opcode v)}))))

(defmulti world-packet
  (fn [v] 
    ;;(debug "Dispatch Val:" (:opcode v))
    (:opcode v)))

(gloss/defcodec world
  (shine/header+
   header

   (fn [header]
      ;;(debug "Header->Body:" header)
      (world-packet 
       (assoc header :opcode
              (:opcode header :unknown-decode))))

   (fn [body] 
     ;;(debug "Body->Header:" body)
     (if (get opcodes (:opcode body))
       body
       (assoc body 
         :opcode :unknown-encode
         :header (:opcode body)
         :body (dissoc body :opcode))))))

;; Use this as a template for multimethods
(defmethod world-packet :template [edn]
  (gloss/finite-frame
   :uint16-be
   (gloss/ordered-map
    :opcode :template
    )))

(defmethod world-packet :auth-session [edn]
  (gloss/finite-frame
   :uint16-be
   (gloss/ordered-map
    :client-build :uint32-le
    :unk-1 (shine/unk :uint32-le 0)
    :I
    (gloss/string :ascii :delimiters [0])
    :client-seed 
    (shine/openssl-bignum :length 4)
    :client-proof 
    (shine/openssl-bignum :length 20)
    ;; Looks like other things are sent but
    ;; no one seems to know what they are.
    :unk-2 shine/black-hole
    )))

(defmethod world-packet :char-enum [edn]
  (gloss/finite-frame
   :uint16-be
   (gloss/ordered-map
    :opcode :char-enum)))

(defmethod world-packet :char-login [edn]
  (gloss/finite-frame
   :uint16-be
   (gloss/ordered-map
    :opcode :char-login
    :guid wow-guid)))

;; Default for Decoding
(defmethod world-packet :unknown-decode [edn]
 ;;(debug "Unknown Realmd Client Decode.")
 (gloss/compile-frame 
  (gloss/ordered-map
   :body (gloss/repeated :ubyte :prefix :none)
   :header (format "0x%X" (:opcode-val edn))
   :opcode :unknown-decode)))

(defmethod world-packet :unknown-encode [edn]
  ;;(debug "Unknown World Client Encode.")
  nil)

(defn encode
  [val]
  (try
   (-> 
    (io/encode world val)
    (into-real-header))
   (catch Exception ex
     (error "World Packet Client Encode:" val)
     nil)))

(defn decode
  [bytes]
  (try
   (io/decode 
    world 
    (into-better-header bytes) 
    false)
   (catch Exception ex
     (error "World Packet Client Decode:" ex)
     {:opcode :error :error ex :bytes bytes})))
