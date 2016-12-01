(defproject helper "0.1.0-SNAPSHOT"

  :description "FIXME: write description"
  
  :url "http://example.com/FIXME"
  
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  
  :dependencies [[org.clojure/clojure "1.8.0"]
                 [org.clojure/core.async "0.2.374"]
                 [org.clojure/tools.cli "0.3.3"]
                 [com.taoensso/timbre "4.3.1"]
                 [aleph "0.4.1"]
                 [gloss "0.2.5"]
                 [mount "0.1.10"]
                 [cprop "0.1.7"]]
  
  :global-vars {*warn-on-reflection* true
                *unchecked-math* true}
  
  :javac-options ["-XX:+TieredCompilation" "-XX:+AggressiveOpts"]
  
  :jvm-opts ["-server" "-Djava.awt.headless=true" "-Djava.net.preferIPv4Stack=true" "-Dsun.net.inetaddr.ttl=60"]
  
  :min-lein-version "2.0.0"

  :main helper.core

  :plugins []
  
  :target-path "target/%s/"

  :profiles {:uberjar {:omit-source true
                       :aot :all
                       :uberjar-name "helper.jar"
                       :source-paths ["src/clj"]}
             
             :test [:project/test :profiles/test]
             
             :project/test {:jvm-opts ["-Dconf=resources/test-config.edn"]
                            :dependencies [[pjstadig/humane-test-output "0.7.1"]]
                            :source-paths ["test/clj"]
                            :repl-options {:init-ns user}
                            :injections [(require 'pjstadig.humane-test-output)
                                         (pjstadig.humane-test-output/activate!)]}
             
             :dev [:project/dev :profiles/dev]
             
             :project/dev  {:jvm-opts ["-Dconf=resources/dev-config.edn"]
                            :dependencies [[pjstadig/humane-test-output "0.7.1"]]
                            :source-paths ["src/clj"]
                            :repl-options {:init-ns api.core}
                            :injections [(require 'pjstadig.humane-test-output)
                                         (pjstadig.humane-test-output/activate!)]}})
