(ns helper.packet.mangosd
  (:require 
   [aleph.tcp :as tcp]
   [gloss.core :as gloss]
   [gloss.io :as io]))

;; TODO: this should handle a byte array.
(defn parse-header
  [header]
  {:len (:b2 header)
   :opcode (bit-or
            (bit-shift-left (:b4 header) 8) 
            (:b3 header))})

(defn decrypt-header
  [header]
  (if (zero? (:b1 header))
    (parse-header header)
    ;; decrypt, then parse
    (println "DECODE PLACEHOLDER!")))

;; TODO: This should read a uint32 and convert to bytes before decrypt.
(gloss/defcodec world-header
  (gloss/compile-frame
   {:b1 :ubyte :b2 :ubyte
    :b3 :ubyte :b4 :ubyte}
   #(println "PRE ENCODE PLACEHOLDER!")
   decrypt-header))

(defmulti world-packet 
  (fn [opcode] opcode))

;;default handling
(defmethod world-packet :default [opcode]
 (println 
  (format "Unknown World Opcode: 0x%04X" opcode))
 (gloss/compile-frame
  (gloss/repeated :ubyte :prefix :none)))

(gloss/defcodec world
  (gloss/header
   world-header
   #(gloss/compile-frame
     (gloss/finite-frame 
      (- (:len %) 2)
      (world-packet (:opcode %))))
   #(println "BODY TO HEADER PLACEHOLDER!")
   ))

