(ns helper.core
  (:require 
   [taoensso.timbre :as timbre :refer [info]]
   [mount.core :as mount])
  (:gen-class))

;; DEV - put this in settings or use MQ
(init
 {:server "127.0.0.1"
  :account-name "hosehead"
  :account-password "wanker"
  :realm "mangos"
  :character "digitalnyx"
  :profile :level-up})

(defn -main [& args]
  (timbre/set-level! :warn)
  (mount/start))

