-- phpMyAdmin SQL Dump
-- version 4.5.1
-- http://www.phpmyadmin.net
--
-- Host: 127.0.0.1
-- Generation Time: Dec 11, 2016 at 02:07 PM
-- Server version: 10.1.9-MariaDB
-- PHP Version: 5.6.15

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `firewall`
--

-- --------------------------------------------------------

--
-- Table structure for table `blacklist`
--

CREATE TABLE `blacklist` (
  `IP` varchar(50) NOT NULL,
  `Attacked` int(11) NOT NULL DEFAULT '1',
  `TTR` datetime NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Table structure for table `input`
--

CREATE TABLE `input` (
  `ID` int(11) NOT NULL,
  `In_Out` varchar(1) NOT NULL DEFAULT '1',
  `Src_IP` varchar(20) NOT NULL,
  `Src_Port` varchar(10) NOT NULL DEFAULT '0',
  `Dest_IP` varchar(20) NOT NULL,
  `Dest_Port` varchar(10) NOT NULL DEFAULT '0',
  `Proto` varchar(1) NOT NULL DEFAULT '0',
  `Action` varchar(1) NOT NULL DEFAULT '0',
  `RSrc_IP` varchar(40) NOT NULL,
  `RDest_IP` varchar(40) NOT NULL,
  `AttackTime` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `input`
--

INSERT INTO `input` (`ID`, `In_Out`, `Src_IP`, `Src_Port`, `Dest_IP`, `Dest_Port`, `Proto`, `Action`, `RSrc_IP`, `RDest_IP`, `AttackTime`) VALUES
(22, '1', '4261521600', '234', '4261521600', '743', '2', '0', '192.168.1.254', '192.168.1.254', '2016-12-11 12:56:13'),
(23, '1', '129313', '23', '213892173', '21', '1', '1', '192.182.12.32', '192.13.13.13', '2016-12-11 12:56:13'),
(24, '1', '129313', '23', '213892173', '21', '1', '1', '192.182.11.32', '192.3.13.13', '2016-12-11 12:56:13'),
(25, '1', '13132', '12', '21312', '3', '1', '1', '192.15.15.1', '192.13.2.1', '2016-12-11 12:56:13'),
(26, '1', '4261521600', '820', '1644275904', '743', '0', '0', '192.168.1.23', '192.168.2.92', '2016-12-11 12:56:13');

--
-- Indexes for dumped tables
--

--
-- Indexes for table `blacklist`
--
ALTER TABLE `blacklist`
  ADD PRIMARY KEY (`IP`);

--
-- Indexes for table `input`
--
ALTER TABLE `input`
  ADD PRIMARY KEY (`ID`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `input`
--
ALTER TABLE `input`
  MODIFY `ID` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=27;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
