// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {ERC20Upgradeable} from "@openzeppelin-upgradeable/contracts/token/ERC20/ERC20Upgradeable.sol";
import {ERC20PermitUpgradeable} from "@openzeppelin-upgradeable/contracts/token/ERC20/extensions/ERC20PermitUpgradeable.sol";
import {Initializable} from "@openzeppelin-upgradeable/contracts/proxy/utils/Initializable.sol";
import {OwnableUpgradeable} from "@openzeppelin-upgradeable/contracts/access/OwnableUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin-upgradeable/contracts/proxy/utils/UUPSUpgradeable.sol";
import {ByteHasher} from "./helpers/ByteHasher.sol";
import {IWorldID} from "./interfaces/IWorldID.sol";

contract Flag is Initializable, ERC20Upgradeable, ERC20PermitUpgradeable, OwnableUpgradeable, UUPSUpgradeable {
    using ByteHasher for bytes;

    error Flag__NotEnoughTimeHasPassed(uint256 lastMintedAt, uint256 requiredWaitTime);
    error Flag__CannotGrabFromSelfAddress(address lastGrabAddress, address msgSender);
    error Flag__CannotGrabFromSelfNullifierHash(uint256 lastGrabNullifierHash, uint256 msgSenderNullifierHash);

    uint256 internal constant GROUP_ID = 1;
    IWorldID internal immutable WORLD_ID;
    uint256 internal immutable EXTERNAL_NULLIFIER;

    uint256 public waitBetweenGrabs;
    uint256 public rewardPerSecond;
    uint256 public maxEarningsPerGrab;

    // Last Grab Data
    uint256 public lastGrabTimestamp;
    address public lastGrabAddress;
    uint256 public lastGrabNullifierHash;

    // Cumulative Data
    uint256 public totalGrabs;

    struct GrabData {
        uint256 lastGrabbedTimestamp;
        uint32 numOfGrabs;
        uint256 totalTimeHeld;
        address lastUsedAddress;
    }

    mapping(uint256 nullifierHash => GrabData) public nullifierHashGrabData;

    // Used to calculate how much a user earned on their prior grab.
    mapping(uint256 nullifierHash => uint256) public nullifierHashToPrevHoldEarnings;

    event Grabbed(address indexed newHolder, address indexed previousHolder, uint256 amount);
    event WaitBetweenGrabsUpdated(uint256 oldWait, uint256 newWait);
    event RewardPerSecondUpdated(uint256 oldReward, uint256 newReward);
    event MaxEarningsPerGrabUpdated(uint256 oldMax, uint256 newMax);
    event TotalTimeHeldUpdated(uint256 indexed nullifierHash, uint256 totalTimeHeld);
    event AddressUsed(uint256 indexed nullifierHash, address indexed userAddress);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor(IWorldID _worldId, string memory _appId, string memory _actionId) {
        WORLD_ID = _worldId;
        EXTERNAL_NULLIFIER = abi.encodePacked(abi.encodePacked(_appId).hashToField(), _actionId).hashToField();
        _disableInitializers();
    }

    function initialize(uint256 _waitBetweenGrabs, uint256 _rewardPerSecond, uint256 _maxEarningsPerGrab) public initializer {
        __ERC20_init("FLAG", "FLAG");
        __ERC20Permit_init("FLAG");
        __Ownable_init(msg.sender);
        __UUPSUpgradeable_init();
        waitBetweenGrabs = _waitBetweenGrabs;
        rewardPerSecond = _rewardPerSecond;
        maxEarningsPerGrab = _maxEarningsPerGrab;
    }

    function grab(uint256 root, uint256 nullifierHash, uint256[8] calldata proof) public returns (uint256 amount) {
        // Ensure the grabber is not the same as the last grabber
        require(msg.sender != lastGrabAddress, Flag__CannotGrabFromSelfAddress(lastGrabAddress, msg.sender));
        require(nullifierHash != lastGrabNullifierHash, Flag__CannotGrabFromSelfNullifierHash(lastGrabNullifierHash, nullifierHash));

        // Ensure the required wait time has passed since the last grab
        GrabData memory grabData = nullifierHashGrabData[nullifierHash];
        if (grabData.lastGrabbedTimestamp != 0) {
            require(
                block.timestamp - grabData.lastGrabbedTimestamp >= waitBetweenGrabs,
                Flag__NotEnoughTimeHasPassed(grabData.lastGrabbedTimestamp, waitBetweenGrabs)
            );
        }

        // Verify proof of personhood
        WORLD_ID.verifyProof(
            root, 
            GROUP_ID, 
            abi.encodePacked(msg.sender).hashToField(), 
            nullifierHash, 
            EXTERNAL_NULLIFIER, 
            proof
        );

        // Calculate time elapsed
        uint256 timeElapsed = block.timestamp - lastGrabTimestamp;

        if (lastGrabAddress != address(0)) {    
            // Record the grab for the previous user, but not if it's the first grab.
            GrabData storage prevHolderData = nullifierHashGrabData[lastGrabNullifierHash];
            prevHolderData.totalTimeHeld += timeElapsed;
            emit TotalTimeHeldUpdated(lastGrabNullifierHash, prevHolderData.totalTimeHeld);

            // Calculate reward for previous holder: 1 FLAG per second, but not if it's the first grab.
            amount = timeElapsed * rewardPerSecond;
            if (amount > maxEarningsPerGrab) {
                amount = maxEarningsPerGrab;
            }
            // Record the previous grab's earning for the previous holder, even if it's 0
            nullifierHashToPrevHoldEarnings[lastGrabNullifierHash] = amount;
            
            if (amount > 0) {
                _mint(lastGrabAddress, amount);
            }
        } else {
            // If it's the first grab, don't mint any tokens.
            amount = 0;
        }

        // Record the grab for the current user
        GrabData storage myData = nullifierHashGrabData[nullifierHash];
        myData.lastGrabbedTimestamp = block.timestamp;
        myData.numOfGrabs++;
        myData.lastUsedAddress = msg.sender;

        emit AddressUsed(nullifierHash, msg.sender);

        // Update the last grabber and timestamp
        address previousGrabber = lastGrabAddress;
        lastGrabAddress = msg.sender;
        lastGrabTimestamp = block.timestamp;
        lastGrabNullifierHash = nullifierHash;
        totalGrabs++;

        emit Grabbed(msg.sender, previousGrabber, amount);
        return amount;
    }

    function setWaitBetweenGrabs(uint256 _waitBetweenGrabs) external onlyOwner {
        emit WaitBetweenGrabsUpdated(waitBetweenGrabs, _waitBetweenGrabs);
        waitBetweenGrabs = _waitBetweenGrabs;
    }

    function setRewardPerSecond(uint256 _rewardPerSecond) external onlyOwner {
        emit RewardPerSecondUpdated(rewardPerSecond, _rewardPerSecond);
        rewardPerSecond = _rewardPerSecond;
    }

    function setMaxEarningsPerGrab(uint256 _maxEarningsPerGrab) external onlyOwner {
        emit MaxEarningsPerGrabUpdated(maxEarningsPerGrab, _maxEarningsPerGrab);
        maxEarningsPerGrab = _maxEarningsPerGrab;
    }

    function getHolderStats(uint256 nullifierHash) public view returns (GrabData memory) {
        GrabData memory data = nullifierHashGrabData[nullifierHash];
        
        // If this is the current holder, add current elapsed time
        if (nullifierHash == lastGrabNullifierHash) {
            data.totalTimeHeld += block.timestamp - lastGrabTimestamp;
        }
        return data;
    }

    function getLastGrabEarnings(uint256 nullifierHash) public view returns (uint256) {
        if (nullifierHash == lastGrabNullifierHash) {
            uint256 amount = (block.timestamp - lastGrabTimestamp) * rewardPerSecond;
            if (amount > maxEarningsPerGrab) {
                amount = maxEarningsPerGrab;
            }
            return amount;
        } else {
            return nullifierHashToPrevHoldEarnings[nullifierHash];
        }
    }

    /// @notice Allows the owner to mint tokens to a specified address
    /// @param to The address to mint tokens to
    /// @param amount The amount of tokens to mint (in wei)
    function mint(address to, uint256 amount) external onlyOwner {
        _mint(to, amount);
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

}
