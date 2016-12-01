(ns helper.packet.utils-test
  (:require [clojure.test :refer :all]
            [helper.packet.utils :refer :all]))

(deftest byte-conversions
  (testing "A single byte can be converted to an integer."
    (is (= 1 (byte 1)))
    (is (= 236 (byte 0xEC)))
    (is (= 236 (first (into-array Byte/TYPE [0xEC]))))
    ))
