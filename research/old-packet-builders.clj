(defn <-logon-challenge
  []
  [{:name :opcode :type :uint-8 :size 1 :desc "OPCode"}
   {:name :error :type :uint-8 :size 1 :desc "Error"}
   {:name :response :type :uint-8 :size 1 :desc "Auth response code"
    :validation-fn
    (fn [this]
      (when-not (zero? this)
        (throw (Exception. ^String (auth-response->string this)))))}
   {:name :B :type :big-num :size 32 :desc "SRP B"}
   {:name :g-size :type :uint-8 :size 1 :desc "Size of g"}
   {:name :g :type :big-num :size :g-size :desc "SRP g"}
   {:name :N-size :type :uint-8 :size 1 :desc "Size of N"}
   {:name :N :type :big-num :size :N-size :desc "SRP N"}
   {:name :s :type :big-num :size 32 :desc "SRP s"}
   {:name :unk3 :type :big-num :size 16 :desc "SRP unk3"}]
  )

(defn logon-proof->
  [A M1]
  [{:val 1 :type :uint-8 :desc "OPCode"}
   {:val A :type :big-num :size 32 :desc "A"}
   {:val M1 :type :big-num :size 20 :desc "M1"}
   {:val :rand :type :big-num :size 20 :desc "CRC"}
   {:val 0 :type :uint-8 :desc "Key Count"}
   {:val 0 :type :uint-8 :desc "Security Flags"}])

(defn <-logon-proof
  []
  [{:name :opcode :type :uint-8 :size 1 :desc "OPCode"}
   {:name :error :type :uint-8 :size 1 :desc "Error"
    :validation-fn
    (fn [this]
      (when-not (zero? this)
        (throw (Exception. "Logon Proof Failure."))))}
   {:name :M2 :type :big-num :size 32 :desc "M2"}])

(defn realm-list->
  []
  [{:val 16 :type :uint-8 :desc "OPCode"}
   {:val 0  :type :uint-8 :desc "Filler"}
   {:val 0  :type :uint-8 :desc "Filler"}
   {:val 0  :type :uint-8 :desc "Filler"}
   {:val 0  :type :uint-8 :desc "Filler"}])

(defn <-realm-list
  [num-realms]
  (vec
   (concat
    [{:name :opcode :type :uint-8 :size 1 :desc "OPCode"}
    {:name :packet-size :type :uint-16 :size 2 :desc "Packet Size"}
    {:name :unk-1 :type :uint-32 :size 4 :desc "Unknown"}
    {:name :realm-list-size :type :uint-8 :size 1 :desc "Number of realms??"}]
    (for [i (range num-realms)]
      {:name :realms :type :object-list :object-number i
       :list
       [{:name :realm-type :type :uint-32 :size 4 :desc "Realm Type"}
        {:name :realm-flags :type :uint-8 :size 1 :desc "Realm Flags"}
        {:name :realm-name :type :c-str :size :unknown :endian :big :desc "Realm Name"}
        {:name :realm-address :type :c-str :size :unknown :endian :big :desc "Realm address"}
        {:name :population-level :type :float :size 4 :desc "Population Level"}
        {:name :num-chars :type :uint-8 :size 1 :desc "Number Characters"}
        {:name :time-zone :type :uint-8 :size 1 :desc "Time Zone"}
        {:name :unk-2 :type :uint-8 :size 1 :desc "Unknown"}]})
   [{:name :unk-3 :type :uint-16 :size 2 :desc "Unknown"}])))
