(ns helper.packet.packer
  (:require
   [helper.packet.utils :refer :all]))

(defn- format-attribute
  [attribute]
    (cond

     (= :uint-8 (:type attribute))
     (int->bytes (:val attribute) 1)

     (= :uint-16 (:type attribute))
     (apply-endianess
       (:endian attribute default-endian)
       (int->bytes (:val attribute) 2))

     (= :uint-32 (:type attribute))
     (apply-endianess
       (:endian attribute default-endian)
       (int->bytes (:val attribute) 4))

     (= :big-num (:type attribute))
     (apply-endianess
      (:endian attribute default-endian)
      (let [v (:val attribute)]
       (if (= :rand v)
         (big-num->bytes
           (BigInteger. ^int (* 8 (:size attribute))
                        (java.util.Random.)))
         (big-num->bytes v))))

     (= :str (:type attribute))
     (apply-endianess
       (:endian attribute default-endian)
       (map byte (:val attribute)))

     (= :c-str (:type attribute))
     (conj
      (apply-endianess
       (:endian attribute default-endian)
       (map byte (:val attribute)))
      0)

     (= :ip-address (:type attribute))
     (apply-endianess
       (:endian attribute default-endian)
       (ip-string->bytes (:val attribute)))

     :else '(0)))

(defn pack
  [attributes]
  (into-array
   Byte/TYPE
   (map unchecked-byte
    (loop [pkt-attributes attributes
           packed-pkt '()]
      (if (nil? pkt-attributes)
        packed-pkt
        (recur
         (next pkt-attributes)
         (concat packed-pkt
                 (format-attribute (first pkt-attributes)))))))))
