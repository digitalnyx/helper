(ns helper.network.world.packet.codecs.player
  (:require
   [gloss.core :as gloss]
   [clojure.string :refer [upper-case]]
   [helper.utils.shine :as shine]
   [helper.utils.conversions :as conv]
   [taoensso.timbre :as timbre
    :refer [log  trace  debug  info  warn  error  fatal]]))

(def wow-gender
  (gloss/enum
   :ubyte
   {:male 0x00
    :female 0x01}))

(def wow-race
  (gloss/enum
   :ubyte
   {:human 0x01
    :orc 0x02
    :dwarf 0x03
    :night-elf 0x04
    :undead 0x05
    :tauren 0x06
    :gnome 0x07
    :troll 0x08}))

(def wow-class
  (gloss/enum
   :ubyte
   {:warrior 0x01
    :paladin 0x02
    :hunter 0x03
    :rogue 0x04
    :priest 0x05
    :shaman 0x07
    :mage 0x08
    :warlock 0x09
    :druid 0x0B}))

(def wow-guid
  (gloss/finite-frame
   8
   (gloss/repeated
    :ubyte
    :prefix :none)))
