(ns helper.env
  (:require [cprop.core :refer :all]
            [cprop.source :refer :all]))

(def env (load-config 
          :file (:conf (from-system-props))))
