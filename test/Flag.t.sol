// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import "forge-std/Test.sol";
import "../src/Flag.sol";
import "./mocks/WorldIDMock.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract FlagTest is Test {
    Flag public implementation;
    Flag public flag;  // This will be our proxy instance
    WorldIDMock public worldIdMock;
    
    address public constant ALICE = address(0x1);
    address public constant BOB = address(0x2);
    address public constant ADMIN = address(0x3);
    uint256 public constant WAIT_BETWEEN_GRABS = 1 hours;
    uint256 public constant INITIAL_REWARD_RATE = 1 ether;  // 1 FLAG per second
    uint256 public constant INITIAL_MAX_EARNINGS = 3600 ether;  // 3600 FLAG max per grab for our tests

    event Grabbed(address indexed newHolder, address indexed previousHolder, uint256 amount);
    event WaitBetweenGrabsUpdated(uint256 oldWait, uint256 newWait);
    event RewardPerSecondUpdated(uint256 oldReward, uint256 newReward);
    event MaxEarningsPerGrabUpdated(uint256 oldMax, uint256 newMax);

    function setUp() public {
        // Deploy WorldID mock
        worldIdMock = new WorldIDMock();

        // Deploy implementation
        implementation = new Flag(
            IWorldID(address(worldIdMock)),
            "app_id",
            "action_id"
        );

        // Prepare initialization data
        bytes memory initData = abi.encodeWithSelector(
            Flag.initialize.selector,
            WAIT_BETWEEN_GRABS,
            INITIAL_REWARD_RATE,
            INITIAL_MAX_EARNINGS
        );

        // Deploy ERC1967 proxy
        vm.prank(ADMIN);
        ERC1967Proxy proxy = new ERC1967Proxy(
            address(implementation),
            initData
        );

        // Create interface to proxy
        flag = Flag(address(proxy));
    }

    function testInitialGrab() public {
        // Set up test data
        uint256 root = 1;
        uint256 nullifierHash = 2;
        uint256[8] memory proof = [uint256(3), 0, 0, 0, 0, 0, 0, 0];

        // Set a known timestamp
        vm.warp(1000);

        // Verify initial contract state
        assertEq(flag.lastGrabAddress(), address(0));
        assertEq(flag.lastGrabTimestamp(), 0);
        assertEq(flag.lastGrabNullifierHash(), 0);
        assertEq(flag.totalGrabs(), 0);
        
        // Capture the previous state that will be used in the event
        address previousGrabber = flag.lastGrabAddress();

        // Set up ALICE as the caller
        vm.prank(ALICE);

        // On the first grab, amount should be 0 bc it's a special case.
        uint256 expectedAmount = 0;

        // Expect the Grabbed event with the exact parameters the contract will use
        vm.expectEmit(true, true, true, true);
        emit Grabbed(ALICE, previousGrabber, expectedAmount);

        // Perform the grab
        uint256 amount = flag.grab(root, nullifierHash, proof);

        // Verify the grab results
        assertEq(amount, expectedAmount, "Amount should be 0 on the first grab");
        assertEq(flag.lastGrabAddress(), ALICE);
        assertEq(flag.lastGrabTimestamp(), block.timestamp);
        assertEq(flag.lastGrabNullifierHash(), nullifierHash);
        assertEq(flag.totalGrabs(), 1);
        assertEq(flag.balanceOf(ALICE), expectedAmount);

        // Verify holder stats
        Flag.GrabData memory stats = flag.getHolderStats(nullifierHash);
        assertEq(stats.numOfGrabs, 1);
        assertEq(stats.totalTimeHeld, 0);
        assertEq(stats.lastGrabbedTimestamp, block.timestamp);
    }

    function testLastGrabEarnings() public {
        uint256 root = 1;
        uint256 nullifierHash1 = 2;
        uint256 nullifierHash2 = 3;
        uint256[8] memory proof = [uint256(3), 0, 0, 0, 0, 0, 0, 0];

        // This test is not testing the max earnings per grab functionality
        vm.prank(ADMIN);
        flag.setMaxEarningsPerGrab(99999999 ether);

        // Set a known timestamp
        vm.warp(1000);

        // First grab by ALICE
        vm.prank(ALICE);
        flag.grab(root, nullifierHash1, proof);

        // Warp forward 1 hour
        vm.warp(block.timestamp + 3600);

        // BOB grabs from ALICE
        vm.prank(BOB);
        flag.grab(root, nullifierHash2, proof);

        // Check ALICE's earnings from her grab
        uint256 aliceEarnings = flag.getLastGrabEarnings(nullifierHash1);
        assertEq(aliceEarnings, 3600 ether, "ALICE should have earned 3600 FLAG");

        // Warp forward another hour
        vm.warp(block.timestamp + 3600);

        // Check BOB's current earnings (he's still holding)
        uint256 bobCurrentEarnings = flag.getLastGrabEarnings(nullifierHash2);
        assertEq(bobCurrentEarnings, 3600 ether, "BOB should be earning 3600 FLAG so far");

        // ALICE grabs back from BOB
        vm.prank(ALICE);
        flag.grab(root, nullifierHash1, proof);

        // Check BOB's final earnings after ALICE grabbed
        uint256 bobFinalEarnings = flag.getLastGrabEarnings(nullifierHash2);
        assertEq(bobFinalEarnings, 3600 ether, "BOB's prior grab should have earned 3600 FLAG");

        // Warp forward another hour
        vm.warp(block.timestamp + 3601);

        // BOB grabs back from ALICE
        vm.prank(BOB);
        flag.grab(root, nullifierHash2, proof);

        // Check ALICE's final earnings
        uint256 aliceFinalEarnings = flag.getLastGrabEarnings(nullifierHash1);
        assertEq(aliceFinalEarnings, 3601 ether, "ALICE's prior grab should have earned 3601 FLAG");
        Flag.GrabData memory aliceStats = flag.getHolderStats(nullifierHash1);
        assertEq(aliceStats.totalTimeHeld, 7201, "ALICE should have held for 7201 seconds in total");
    }

    function testCannotGrabTooSoon() public {
        uint256 root = 1;
        uint256 nullifierHash = 2;
        uint256[8] memory proof = [uint256(3), 0, 0, 0, 0, 0, 0, 0];

        // First grab succeeds with ALICE
        vm.prank(ALICE);
        flag.grab(root, nullifierHash, proof);
        uint256 firstGrabTime = block.timestamp;

        // Try to grab again before wait time has passed
        vm.warp(block.timestamp + 1);
        vm.prank(BOB);
        flag.grab(root, 3, proof);

        vm.warp(block.timestamp + 1);
        vm.prank(ALICE);
        vm.expectRevert(abi.encodeWithSelector(
            Flag.Flag__NotEnoughTimeHasPassed.selector,
            firstGrabTime,
            WAIT_BETWEEN_GRABS
        ));
        flag.grab(root, nullifierHash, proof);
    }

    function testMultipleGrabs() public {
        uint256 root = 1;
        uint256[8] memory proof = [uint256(3), 0, 0, 0, 0, 0, 0, 0];

        // ALICE grabs first
        vm.prank(ALICE);
        flag.grab(root, 1, proof);
        uint256 aliceGrabTime = block.timestamp;

        // Wait required time
        vm.warp(block.timestamp + WAIT_BETWEEN_GRABS);

        // BOB grabs from ALICE
        vm.prank(BOB);
        flag.grab(root, 2, proof);

        // Check ALICE's stats after BOB's grab
        Flag.GrabData memory aliceStats = flag.getHolderStats(1);
        assertEq(aliceStats.numOfGrabs, 1, "Should record grab");
        assertEq(aliceStats.totalTimeHeld, WAIT_BETWEEN_GRABS, "Should record full time held");
        assertEq(flag.balanceOf(ALICE), WAIT_BETWEEN_GRABS * INITIAL_REWARD_RATE, "ALICE should get reward for holding");

        // Wait and let ALICE grab again
        vm.warp(block.timestamp + WAIT_BETWEEN_GRABS);
        vm.prank(ALICE);
        flag.grab(root, 1, proof);

        // Check BOB's final stats
        Flag.GrabData memory bobStats = flag.getHolderStats(2);
        assertEq(bobStats.numOfGrabs, 1, "Should record grab count");
        assertEq(bobStats.totalTimeHeld, WAIT_BETWEEN_GRABS, "Should record full time held");
        assertEq(flag.balanceOf(BOB), WAIT_BETWEEN_GRABS * INITIAL_REWARD_RATE, "BOB should get reward for holding");

        vm.warp(block.timestamp + WAIT_BETWEEN_GRABS);

        // Check ALICE's final stats
        aliceStats = flag.getHolderStats(1);
        assertEq(aliceStats.numOfGrabs, 2, "Should record new grab");
        assertEq(aliceStats.totalTimeHeld, WAIT_BETWEEN_GRABS * 2, "Should update total time held");
    }

    function testWorldIDVerification() public {
        uint256 root = 1;
        uint256 nullifierHash = 2;
        uint256[8] memory invalidProof = [uint256(999), 0, 0, 0, 0, 0, 0, 0];

        // Configure the WorldIDMock to fail verification
        worldIdMock.setVerificationResult(false);

        vm.prank(ALICE);
        vm.expectRevert();
        flag.grab(root, nullifierHash, invalidProof);

        // Verify no state changes occurred
        assertEq(flag.lastGrabAddress(), address(0), "Last grabber should not be set");
        assertEq(flag.balanceOf(ALICE), 0, "No tokens should be minted");
        
        // Verify no stats were recorded
        Flag.GrabData memory stats = flag.getHolderStats(nullifierHash);
        assertEq(stats.numOfGrabs, 0, "Should not record failed grab");
        assertEq(stats.totalTimeHeld, 0, "Should not record any time held");
    }

    function testCannotGrabFromSelf() public {
        uint256 root = 1;
        uint256 nullifierHash = 2;
        uint256[8] memory proof = [uint256(3), 0, 0, 0, 0, 0, 0, 0];

        // First grab by ALICE
        vm.prank(ALICE);
        flag.grab(root, nullifierHash, proof);

        // Wait enough time
        vm.warp(block.timestamp + WAIT_BETWEEN_GRABS);

        // Try to grab with same address
        vm.prank(ALICE);
        vm.expectRevert(abi.encodeWithSelector(
            Flag.Flag__CannotGrabFromSelfAddress.selector,
            ALICE,  // lastGrabAddress is still ALICE
            ALICE
        ));
        flag.grab(root, 3, proof); // different nullifier

        // Try to grab with different address but same nullifier
        vm.prank(BOB);
        vm.expectRevert(abi.encodeWithSelector(
            Flag.Flag__CannotGrabFromSelfNullifierHash.selector,
            nullifierHash,
            nullifierHash
        ));
        flag.grab(root, nullifierHash, proof);
    }

    function testSetWaitBetweenGrabs() public {
        uint256 newWaitTime = 2 hours;

        // Try to update wait time from non-admin address
        vm.prank(ALICE);
        vm.expectRevert();
        flag.setWaitBetweenGrabs(newWaitTime);

        // Update wait time from admin
        vm.prank(ADMIN);
        vm.expectEmit(true, true, true, true);
        emit WaitBetweenGrabsUpdated(WAIT_BETWEEN_GRABS, newWaitTime);
        flag.setWaitBetweenGrabs(newWaitTime);

        assertEq(flag.waitBetweenGrabs(), newWaitTime, "Wait time should be updated");
    }

    function testCannotReinitialize() public {
        vm.expectRevert(abi.encodeWithSignature("InvalidInitialization()"));
        flag.initialize(WAIT_BETWEEN_GRABS, INITIAL_REWARD_RATE, INITIAL_MAX_EARNINGS);
    }

    function testUpgradeability() public {
        // First do a grab to set some state
        uint256 root = 1;
        uint256 nullifierHash = 2;
        uint256[8] memory proof = [uint256(3), 0, 0, 0, 0, 0, 0, 0];

        vm.prank(ALICE);
        flag.grab(root, nullifierHash, proof);

        // Record state before upgrade
        address lastGrabber = flag.lastGrabAddress();
        uint256 lastNullifier = flag.lastGrabNullifierHash();
        uint256 totalGrabs = flag.totalGrabs();
        uint256 waitTime = flag.waitBetweenGrabs();

        // Deploy new implementation
        Flag newImplementation = new Flag(
            IWorldID(address(worldIdMock)),
            "app_id",
            "action_id"
        );

        // Only owner can upgrade the implementation
        bytes memory expectedError = abi.encodeWithSignature("OwnableUnauthorizedAccount(address)", ALICE);
        vm.expectRevert(expectedError);
        vm.prank(ALICE);
        flag.upgradeToAndCall(address(newImplementation), "");

        // Owner can upgrade the implementation
        vm.prank(ADMIN);
        flag.upgradeToAndCall(address(newImplementation), "");

        // Verify all state was preserved after upgrade
        assertEq(flag.lastGrabAddress(), lastGrabber, "Last grabber should be preserved");
        assertEq(flag.lastGrabNullifierHash(), lastNullifier, "Last nullifier should be preserved");
        assertEq(flag.totalGrabs(), totalGrabs, "Total grabs should be preserved");
        assertEq(flag.waitBetweenGrabs(), waitTime, "Wait time should be preserved");

        
        // Verify we can still interact with the contract through the proxy
        vm.warp(block.timestamp + waitTime);
        vm.prank(BOB);
        flag.grab(root, 3, proof);
        
        // Verify the interaction worked
        assertEq(flag.lastGrabAddress(), BOB, "Should update last grabber");
        assertEq(flag.totalGrabs(), totalGrabs + 1, "Should increment total grabs");
    }

    function testSubsequentGrab() public {
        uint256 root = 1;
        uint256 nullifierHash1 = 2;
        uint256 nullifierHash2 = 3;
        uint256[8] memory proof = [uint256(3), 0, 0, 0, 0, 0, 0, 0];

        // First grab by ALICE
        vm.prank(ALICE);
        flag.grab(root, nullifierHash1, proof);

        // Wait for the required time
        vm.warp(block.timestamp + WAIT_BETWEEN_GRABS);

        // BOB grabs from ALICE
        vm.prank(BOB);
        flag.grab(root, nullifierHash2, proof);

        // Check ALICE's stats
        Flag.GrabData memory aliceStats = flag.getHolderStats(nullifierHash1);
        assertEq(aliceStats.numOfGrabs, 1, "Should record first grab");
        assertEq(aliceStats.totalTimeHeld, WAIT_BETWEEN_GRABS, "Should record time held");
        assertEq(flag.balanceOf(ALICE), WAIT_BETWEEN_GRABS * INITIAL_REWARD_RATE, "ALICE should get reward for holding");

        // Check BOB's initial stats
        Flag.GrabData memory bobStats = flag.getHolderStats(nullifierHash2);
        assertEq(bobStats.numOfGrabs, 1, "Should record first grab");
        assertEq(bobStats.totalTimeHeld, 0, "Initial holder starts with 0 time");
    }

    function testPermit() public {
        uint256 ownerPrivateKey = 0x1234;
        address owner = vm.addr(ownerPrivateKey);
        address spender = address(0x5678);
        uint256 value = 100 ether;
        uint256 deadline = block.timestamp + 1 hours;
        
        // Get current nonce
        uint256 nonce = flag.nonces(owner);
        
        // Create permit signature
        bytes32 domainSeparator = flag.DOMAIN_SEPARATOR();
        bytes32 permitHash = keccak256(
            abi.encodePacked(
                "\x19\x01",
                domainSeparator,
                keccak256(
                    abi.encode(
                        keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"),
                        owner,
                        spender,
                        value,
                        nonce,
                        deadline
                    )
                )
            )
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, permitHash);

        // Execute permit
        flag.permit(owner, spender, value, deadline, v, r, s);

        // Verify allowance was set
        assertEq(flag.allowance(owner, spender), value);
        assertEq(flag.nonces(owner), nonce + 1);
    }

    function testRewardRate() public {
        uint256 root = 1;
        uint256 nullifierHash1 = 2;
        uint256 nullifierHash2 = 3;
        uint256[8] memory proof = [uint256(3), 0, 0, 0, 0, 0, 0, 0];

        // This test is not testing the reward rate functionality
        vm.prank(ADMIN);
        flag.setMaxEarningsPerGrab(99999999 ether);

        // First grab by ALICE
        vm.prank(ALICE);
        flag.grab(root, nullifierHash1, proof);

        // Warp forward 1 hour
        vm.warp(block.timestamp + 3600);

        // Set a new reward rate (2 FLAG per second)
        vm.prank(ADMIN);
        vm.expectEmit(true, true, true, true);
        emit RewardPerSecondUpdated(INITIAL_REWARD_RATE, 2 ether);
        flag.setRewardPerSecond(2 ether);

        // BOB grabs from ALICE
        vm.prank(BOB);
        uint256 amount = flag.grab(root, nullifierHash2, proof);

        // Should earn 2 FLAG per second for 3600 seconds = 7200 FLAG
        assertEq(amount, 7200 ether, "Should earn at new reward rate");
    }

    function testMaxEarnings() public {
        uint256 root = 1;
        uint256 nullifierHash1 = 2;
        uint256 nullifierHash2 = 3;
        uint256[8] memory proof = [uint256(3), 0, 0, 0, 0, 0, 0, 0];

        // First grab by ALICE
        vm.prank(ALICE);
        flag.grab(root, nullifierHash1, proof);

        // Warp forward 10 hours
        vm.warp(block.timestamp + 10 hours);

        // Set a lower max earnings (1000 FLAG)
        vm.prank(ADMIN);
        vm.expectEmit(true, true, true, true);
        emit MaxEarningsPerGrabUpdated(INITIAL_MAX_EARNINGS, 300 ether);
        flag.setMaxEarningsPerGrab(300 ether);

        // BOB grabs from ALICE
        vm.prank(BOB);
        uint256 amount = flag.grab(root, nullifierHash2, proof);

        // Even though ALICE held for 10 hours (36000 FLAG potential), 
        // earnings should be capped at 300 FLAG
        assertEq(amount, 300 ether, "Earnings should be capped at max");
    }

    function testOwnershipTransfer() public {
        address newAdmin = address(0x1234);

        // Check initial admin
        assertEq(flag.owner(), ADMIN);

        // Non-admin cannot transfer ownership
        vm.prank(ALICE);
        vm.expectRevert(abi.encodeWithSignature("OwnableUnauthorizedAccount(address)", ALICE));
        flag.transferOwnership(newAdmin);

        // Admin can transfer ownership
        vm.prank(ADMIN);
        flag.transferOwnership(newAdmin);

        // Check new admin
        assertEq(flag.owner(), newAdmin);

        // Old admin can't upgrade anymore
        Flag newImplementation = new Flag(
            IWorldID(address(worldIdMock)),
            "app_id",
            "action_id"
        );

        vm.prank(ADMIN);
        vm.expectRevert(abi.encodeWithSignature("OwnableUnauthorizedAccount(address)", ADMIN));
        flag.upgradeToAndCall(address(newImplementation), "");

        // New admin can upgrade
        vm.prank(newAdmin);
        flag.upgradeToAndCall(address(newImplementation), "");
    }

        function testStateResetOnNewGrab() public {
            uint256 root = 1;
            uint256 nullifierHash1 = 2;
            uint256 nullifierHash2 = 3;
            uint256[8] memory proof = [uint256(3), 0, 0, 0, 0, 0, 0, 0];

            // First grab by ALICE
            vm.prank(ALICE);
            flag.grab(root, nullifierHash1, proof);

            // Warp forward
            vm.warp(block.timestamp + WAIT_BETWEEN_GRABS);

            // Record ALICE's earnings before BOB grabs
            uint256 aliceEarningsBeforeGrab = flag.getLastGrabEarnings(nullifierHash1);

            // BOB grabs from ALICE
            vm.prank(BOB);
            flag.grab(root, nullifierHash2, proof);

            // Verify ALICE's final earnings are recorded correctly
            uint256 aliceFinalEarnings = flag.nullifierHashToPrevHoldEarnings(nullifierHash1);
            assertEq(aliceFinalEarnings, aliceEarningsBeforeGrab, "Final earnings should match last calculated earnings");

            // Verify BOB's initial earnings are 0
            uint256 bobInitialEarnings = flag.nullifierHashToPrevHoldEarnings(nullifierHash2);
            assertEq(bobInitialEarnings, 0, "Initial earnings should be 0");
        }

        function testZeroTimestampGrab() public {
            uint256 root = 1;
            uint256 nullifierHash = 2;
            uint256[8] memory proof = [uint256(3), 0, 0, 0, 0, 0, 0, 0];

            // Set block.timestamp to 0
            vm.warp(0);

            // First grab should work even at timestamp 0
            vm.prank(ALICE);
            uint256 amount = flag.grab(root, nullifierHash, proof);
            assertEq(amount, 0, "First grab should mint 0 tokens");
            assertEq(flag.lastGrabTimestamp(), 0, "Timestamp should be 0");
        }

        function testZeroRewardRate() public {
            uint256 root = 1;
            uint256 nullifierHash1 = 2;
            uint256 nullifierHash2 = 3;
            uint256[8] memory proof = [uint256(3), 0, 0, 0, 0, 0, 0, 0];

            // First grab by ALICE
            vm.prank(ALICE);
            flag.grab(root, nullifierHash1, proof);

            // Set reward rate to 0
            vm.prank(ADMIN);
            flag.setRewardPerSecond(0);

            // Warp forward
            vm.warp(block.timestamp + WAIT_BETWEEN_GRABS);

            // BOB grabs from ALICE
            vm.prank(BOB);
            uint256 amount = flag.grab(root, nullifierHash2, proof);

            // Should mint 0 tokens due to 0 reward rate
            assertEq(amount, 0, "Should mint 0 tokens with 0 reward rate");
            assertEq(flag.balanceOf(ALICE), 0, "ALICE should have 0 tokens");
        }

        function testMaxUint256Values() public {
            uint256 root = 1;
            uint256 nullifierHash1 = 2;
            uint256 nullifierHash2 = 3;
            uint256[8] memory proof = [uint256(3), 0, 0, 0, 0, 0, 0, 0];

            // First grab by ALICE
            vm.prank(ALICE);
            flag.grab(root, nullifierHash1, proof);

            // Set max possible reward rate
            vm.prank(ADMIN);
            flag.setRewardPerSecond(type(uint256).max);

            // Set max possible earnings cap
            vm.prank(ADMIN);
            flag.setMaxEarningsPerGrab(type(uint256).max);

            // Warp forward
            vm.warp(block.timestamp + 1); // Just 1 second, to avoid overflow

            // BOB grabs from ALICE
            vm.prank(BOB);
            uint256 amount = flag.grab(root, nullifierHash2, proof);

            // Should not overflow
            assertEq(amount, type(uint256).max, "Should cap at max uint256");
        }

        function testGrabbedEventAmount() public {
            uint256 root = 1;
            uint256 nullifierHash1 = 2;
            uint256 nullifierHash2 = 3;
            uint256[8] memory proof = [uint256(3), 0, 0, 0, 0, 0, 0, 0];

            // First grab by ALICE
            vm.prank(ALICE);
            vm.expectEmit(true, true, true, true);
            emit Grabbed(ALICE, address(0), 0); // First grab should emit 0 amount
            flag.grab(root, nullifierHash1, proof);

            // Warp forward 1 hour
            vm.warp(block.timestamp + WAIT_BETWEEN_GRABS);

            // BOB grabs from ALICE
            vm.prank(BOB);
            uint256 expectedAmount = WAIT_BETWEEN_GRABS * INITIAL_REWARD_RATE;
            vm.expectEmit(true, true, true, true);
            emit Grabbed(BOB, ALICE, expectedAmount);
            flag.grab(root, nullifierHash2, proof);
        }

        function testInitializationState() public {
            // Deploy new implementation and proxy for this test
            Flag newImplementation = new Flag(
                IWorldID(address(worldIdMock)),
                "app_id",
                "action_id"
            );

            bytes memory initData = abi.encodeWithSelector(
                Flag.initialize.selector,
                WAIT_BETWEEN_GRABS,
                INITIAL_REWARD_RATE,
                INITIAL_MAX_EARNINGS
            );

            vm.prank(ADMIN);
            ERC1967Proxy proxy = new ERC1967Proxy(
                address(newImplementation),
                initData
            );

            Flag newFlag = Flag(address(proxy));

            // Verify all state variables are properly initialized
            assertEq(newFlag.waitBetweenGrabs(), WAIT_BETWEEN_GRABS);
            assertEq(newFlag.rewardPerSecond(), INITIAL_REWARD_RATE);
            assertEq(newFlag.maxEarningsPerGrab(), INITIAL_MAX_EARNINGS);
            assertEq(newFlag.lastGrabTimestamp(), 0);
            assertEq(newFlag.lastGrabAddress(), address(0));
            assertEq(newFlag.lastGrabNullifierHash(), 0);
            assertEq(newFlag.totalGrabs(), 0);
            assertEq(newFlag.owner(), ADMIN);
        }

        function testUpgradeStatePreservation() public {
            // First grab by ALICE
            uint256 root = 1;
            uint256 nullifierHash = 2;
            uint256[8] memory proof = [uint256(3), 0, 0, 0, 0, 0, 0, 0];
            
            vm.prank(ALICE);
            flag.grab(root, nullifierHash, proof);

            // Record state before upgrade
            uint256 totalGrabsBefore = flag.totalGrabs();
            address lastGrabberBefore = flag.lastGrabAddress();
            uint256 lastGrabTimestampBefore = flag.lastGrabTimestamp();
            uint256 lastGrabNullifierHashBefore = flag.lastGrabNullifierHash();

            // Deploy new implementation
            Flag newImplementation = new Flag(
                IWorldID(address(worldIdMock)),
                "app_id",
                "action_id"
            );

            // Upgrade
            vm.prank(ADMIN);
            flag.upgradeToAndCall(address(newImplementation), "");

            // Verify state is preserved
            assertEq(flag.totalGrabs(), totalGrabsBefore);
            assertEq(flag.lastGrabAddress(), lastGrabberBefore);
            assertEq(flag.lastGrabTimestamp(), lastGrabTimestampBefore);
            assertEq(flag.lastGrabNullifierHash(), lastGrabNullifierHashBefore);
        }
    }
