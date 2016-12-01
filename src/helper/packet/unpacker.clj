(ns helper.packet.unpacker
  (:require
   [helper.packet.utils :refer :all]))

(defn- format-attribute
  [attribute byts]
  (cond
     (= :uint-8 (:type attribute))
     (bytes->int byts)

     (= :uint-16 (:type attribute))
     (bytes->int
       (apply-endianess
         (:endian attribute default-endian)
         byts))

     (= :uint-32 (:type attribute))
     (bytes->int
       (apply-endianess
         (:endian attribute default-endian)
         byts))

     (= :float (:type attribute))
     (bytes->float
      (apply-endianess
         (:endian attribute default-endian)
         byts))

     (= :big-num (:type attribute))
     (bytes->big-num
       (apply-endianess
         (:endian attribute default-endian)
         byts))

     (= :str (:type attribute))
     (String.
      ^bytes
      (seq->bytes
       (apply-endianess
        (:endian attribute default-endian)
        byts)))

     (= :c-str (:type attribute))
     (String.
      ^bytes
      (seq->bytes
       (apply-endianess
        (:endian attribute default-endian)
        ;; Remove null term
        (take (dec (:size attribute)) byts))))

     :else
     (throw (Exception.
              (str "Unknown Attribute Type: "
                   (:type attribute))))))

(defn- determine-attribute-size
  [attribute data raw-bytes]
    (if (keyword? (:size attribute))
      (cond

       ;; C String with unknown size
       (and (= :c-str (:type attribute))
            (= :unknown (:size attribute)))
       (first-index-of raw-bytes 0)

       ;; must be in a previously parsed value.
       :else
       ((:size attribute) data))

      ;; Size already known
      (:size attribute)))

(defn- unpacker
  [attributes raw-bytes]
  (loop [attribs attributes
         remaining-bytes raw-bytes
         data {}]
    (if (nil? attribs)
      {:data data :remaining-bytes remaining-bytes}

      (let [attribute (first attribs)]

        (if (:list attribute)
          ;; list of attributes
          (let [unpacked (unpacker (:list attribute) remaining-bytes)]
            (recur (next attribs)
                   (drop (- (count remaining-bytes)
                            (count (:remaining-bytes unpacked)))
                         remaining-bytes)
                   (assoc data (:name attribute)
                               (vec (cons (:data unpacked) ((:name attribute) data '()))))))

         ;; Single Attribute
         (let [size-of (determine-attribute-size
                        attribute data remaining-bytes)
               frmtd (format-attribute
                      (assoc attribute :size size-of)
                      (take size-of remaining-bytes))]

           (when-let [vfn (:validation-fn attribute)]
             (vfn frmtd))

           (recur (next attribs)
                  (drop size-of remaining-bytes)
                  (assoc data (:name attribute) frmtd))))))))

(defn unpack
  [attributes raw-bytes]
  (:data (unpacker attributes raw-bytes)))

