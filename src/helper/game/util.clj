(ns helper.game.util
  (:require
    [taoensso.timbre :as timbre
     :refer [log  trace  debug  info  warn  error  fatal]]))

;; Convenience function
(defn set-state
  [player state]
  (debug "Setting player state:" state)
  (swap! player assoc :state state))

(defn get-state
  [player]
  (:state @player))

(defn get-realm
  ;; Check if the realm we want is authed
  [player]
  ;; TODO: find the actual realm from the player prefs
  (first (get-in @player [:auth :realms])))