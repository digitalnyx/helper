(ns helper.network.world.packet.server
  (:require
   [gloss.core :as gloss]
   [gloss.io :as io]
   [helper.utils.shine :as shine]
   [helper.utils.conversions :as conv]
   [helper.network.world.packet.codecs.player
    :refer [wow-race wow-class wow-gender wow-guid]]
   [taoensso.timbre :as timbre
    :refer [log  trace  debug  info  warn  error  fatal]]))

(def opcodes
  {:char-enum 0x03B
   :auth-challenge 0x1EC
   :auth-response 0x1EE
   })

(def rev-opcodes
  (clojure.set/map-invert opcodes))

;; Swap upper and lower 2 bytes and subtract
;; 2 from the packet length
(gloss/defcodec real-header
  (gloss/ordered-map
   :packet-length :uint16-be
   :opcode :uint16-le
   :body (gloss/repeated :ubyte :prefix :none)))

(gloss/defcodec better-header
  (gloss/ordered-map
   :opcode :uint16-le
   :packet-length :uint16-be
   :body (gloss/repeated :ubyte :prefix :none)))

(defn into-better-header
  ;; Convert incoming bytes to a more user friendly
  [bytes]
  (let [in (io/decode real-header bytes)]
   (io/encode better-header
              {:opcode (:opcode in)
               :packet-length (- (:packet-length in) 2)
               :body (:body in)})))

(defn into-real-header
  ;; Return outgoing bytes to the real header format
  [bytes]
  (let [out (io/decode better-header bytes)]
    (io/encode real-header
               {:opcode (:opcode out)
                :packet-length (+ (:packet-length out) 2)
                :body (:body out)})))

(def header
   (gloss/compile-frame
    (gloss/ordered-map
     :opcode :uint16-le)
    (fn [v] 
      ;;(debug "Header Encode:" v)
      (if-let [opcode (get opcodes (:opcode v))]
        {:opcode opcode}
        {:opcode 0xFFFF}))
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

;; Some servers will send other encryption values
;; after the seed but they are not required for
;; anything as far as I can tell.
(defmethod world-packet :auth-challenge
  [edn]
  (gloss/finite-frame
   :uint16-be
   (gloss/ordered-map
    :server-seed (shine/openssl-bignum :length 4)
    :opcode :auth-challenge
    :unk-1 shine/black-hole
    ;; TODO: Implement a 'maybe' repeat (can be zero)
    ;; Sometimes 16 byte seed-1
    ;; Sometimes 16 byte seed-2
    )))

;; Only sent on success on MaNGOS
(defmethod world-packet :auth-response [edn]
  (gloss/finite-frame
   :uint16-be
   (gloss/ordered-map
    :opcode :auth-response
    :error :ubyte
    :billing-time-remaining
    (shine/unk :uint32-le 0)
    :billing-plan-flags
    (shine/unk :ubyte 0)
    :billing-time-reset
    (shine/unk :uint32-le 0))))

(defmethod world-packet :char-enum [edn]
  (gloss/finite-frame
   :uint16-be
   (gloss/ordered-map
    :opcode :char-enum
    :chars
    (gloss/repeated
     (gloss/ordered-map
      :guid wow-guid
      :name 
      (gloss/string :ascii :delimiters [0])
      :appearance
      (gloss/ordered-map 
       :race wow-race
       :class wow-class
       :gender wow-gender
       :skin :ubyte
       :face :ubyte
       :hair-style :ubyte
       :hair-color :ubyte
       :facial-hair :ubyte)
      :level :ubyte
      :location
      (gloss/ordered-map
       :zone :uint32-le
       :map :uint32-le
       :x :float32-le
       :y :float32-le
       :z :float32-le)
      :guild-id :uint32-le
      :char-flags :uint32-le
      :first-login :ubyte
      :pet
      (gloss/ordered-map
       :pet-display-id :uint32-le
       :pet-level :uint32-le
       :pet-family :uint32-le)
      :inventory-slots
      ;; Note, last bag is always backpack (0, 0)
      (gloss/finite-frame
       100 ;; 20 slots
       (gloss/repeated
        (gloss/ordered-map
         :display-id :uint32-le
         ;; TODO: Use Enums
         :inventory-type :ubyte)
        :prefix :none)))
     :prefix :ubyte))))

;; Default for Decoding
(defmethod world-packet :unknown-decode [edn]
 ;;(debug "Unknown World Server Decode.")
 (gloss/compile-frame 
  (gloss/ordered-map
   :body (gloss/repeated :ubyte :prefix :none)
   :header (format "0x%X" (:opcode-val edn))
   :opcode :unknown-decode)))

(defmethod world-packet :unknown-encode [edn]
  ;;(debug "Unknown World Server Client Encode.")
  nil)

;; TODO: Add encryption options function
(defn encode
  [val]
  (try
   (-> 
    (io/encode world val)
    (into-real-header))
   (catch Exception ex
     (error "World Packet Server Encode:" val)
     nil)))

(defn decode
  [bytes]
  (try
   (io/decode 
    world 
    (into-better-header bytes) 
    false)
   (catch Exception ex
     (error "World Packet Server Decode:" ex)
     {:opcode :error 
      :error ex 
      :bytes (conv/heap->hex bytes)})))
