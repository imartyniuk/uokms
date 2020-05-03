# uokms

Oblivious Key Management System which supports Update operation.

To compile everything run:
`javac -d out src/*.java`
or (recommended):
`mvn compile` from the root repository.

To build the package run:
`mvn package`

To start the KeyManager run:
`java -cp target/kms.jar main.java.org.illiam.uokms.KeyManager`

To start the Storage run:
`java -cp target/storage.jar main.java.org.illiam.uokms.Storage`

To start the Client in the SIMULATION mode run:
`java -cp target/client.jar main.java.org.illiam.uokms.Client -s`

To start the Client in the INTERACTIVE mode run:
`java -cp target/client.jar main.java.org.illiam.uokms.Client -i`
