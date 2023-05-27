(ns helper.utils.streams
  (:require 
   [manifold.stream :as s]
   [clojure.core.async :as async]
   [gloss.core :as gloss]
   [gloss.io :as io]
   [helper.utils.shine :as shine]
   [helper.utils.conversions :as conv]))

(def ts (s/stream))

;;(def buf (async/chan 4096))

(def buf (atom (clojure.lang.PersistentQueue/EMPTY)))

(def head
  (gloss/ordered-map
   :packet-length :uint16-be
   :opcode :uint16-le))

(def th-1
  (conv/into-bb
   [0x0 0x02 0x01 0x00]))

(def th-2
  (conv/into-bb
   [0x0 0x02 0x01 0x00 0x01 0x02 0x03 0x04 0x05]))

