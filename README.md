# uokms

Updatable Oblivious Key Management System

To compile everything run:
`javac -d out src/*.java`
or (recommended):
`mvn compile` from the root repository.

To rebuild the package run:
`mvn clean package`

To start the KeyManager run:
`java -cp target/kms.jar org.illiam.uokms.KeyManager 1024`

To start the Client run:
`java -cp target/client.jar org.illiam.uokms.Client`
