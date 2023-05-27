(ns helper.core
  (:require 
   [taoensso.timbre :as timbre :refer [info]]
   [mount.core :as mount])
  (:gen-class))

;; DEV - put this in settings or use MQ

(defn -main [& args]
  (timbre/set-level! :warn)
  (mount/start))

