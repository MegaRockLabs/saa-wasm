# bundle crate
cd packages/protos && cargo package --allow-dirty && cd ../..
cd packages/types && cargo package --allow-dirty && cd ../..
cd packages/bundle && cargo package --allow-dirty && cd ../..
echo "All packages checked and ready to be published"