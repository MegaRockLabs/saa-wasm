cd packages/protos && cargo publish && cd ../..
sleep 10
cd packages/types && cargo publish && cd ../..
sleep 10
cd packages/bundle && cargo publish && cd ../..
echo "All packages published"