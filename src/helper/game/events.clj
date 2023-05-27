(ns helper.game.events
  (:require
   [helper.game.actions :as action]
   [taoensso.timbre :as timbre
      :refer [log  trace  debug  info  warn  error  fatal]]))

(defmulti process
  (fn [player packet] (:opcode packet)))

(defmethod process :logon-challenge
  [player packet]
  (if (= :success (:errcode packet))
    (do
      (swap! player assoc-in [:auth :challenge] packet)
      (action/send-logon-proof player))
    (do
      (error "Logon Challenge Error:" packet)
      (swap! player assoc :state :fatal-error))))

(defmethod process :logon-proof
  [player packet]
  (if (= :success (:errcode packet))
    (do
      (swap! player assoc-in [:auth :proof] packet)
      (action/send-realm-list player))
    (do
      (error "Logon Proof Error:" packet)
      (swap! player assoc :state :fatal-error))))

(defmethod process :realm-list
  [player packet]
  (swap! player assoc-in [:auth :realms] (:realms packet))
  (swap! player assoc :state :authed)
  (debug "Realm: " packet)
  )

(defmethod process :auth-challenge
  [player packet]
  (action/send-auth-challenge 
   player
   (:server-seed packet)))

(defmethod process :auth-response
  [player packet]
  (action/send-char-enum
   player))

;; Check if our char is listed.
;; TODO: Create it?
(defmethod process :char-enum
  [player packet]
  (let [char-to-find (get-in @player [:account :char])
        fltr #(= char-to-find (:name %)) 
        filtered (filter fltr (:chars packet))]
    ;;(debug (pr-str filtered))
    (if-let [char (first filtered)]
      (action/send-char-login 
       player (:guid char))
      (do
        (error "Failed to find Char:" char-to-find)
        (swap! player assoc :state :fatal-error)))))

(defmethod process :default
  [player packet]
  (debug "Unhandled Packet:" packet))

(defmethod process :unknown-decode
  [player packet]
  (debug "Unknown Packet:" (:header packet))
  ;(swap! player assoc :state :fatal-error)
  )

(defmethod process :error
  [player packet]
  (error "Packet: " packet)
  (error "Setting :state to :fatal-error")
  (swap! player assoc :state :fatal-error))

