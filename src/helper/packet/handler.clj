(ns helper.packet.handler
  (:require ))

(def realm-opcodes
  {:not-found 0})

(defmulti handle-realm-packet 
  (fn [packet] [(nth packet (:not-found realm-opcodes))]))

(defmethod handle-realm-packet 
  (:not-found realm-opcodes) [packet]
  ;; Oh No!
  )

(def world-opcodes
  {:not-found 0})

(defmulti handle-world-packet 
  (fn [packet] [(nth packet (:not-found world-opcodes))]))

(defmethod handle-world-packet 
  (:not-found world-opcodes) [packet]
  ;; Oh No!
  )
