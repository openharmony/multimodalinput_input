#!/system/bin/sh
# Multi-group binding system test wrapper
echo "=== Multi-Group Binding System Test ==="
echo "Step 1: Baseline hidumper"
hidumper -s 3101 -a -G
echo ""
echo "Step 2: Run binding test"
/data/local/tmp/multi_group_binding_real_service_test
echo ""
echo "Step 3: Final hidumper"
hidumper -s 3101 -a -G
echo ""
echo "Step 4: Check evidence files"
ls -la /data/local/tmp/real_svc_*.txt 2>/dev/null
echo "=== DONE ==="
