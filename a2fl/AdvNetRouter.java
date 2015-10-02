package net.floodlightcontroller.advnet;

import java.io.IOException;
import java.util.Collection;
import java.util.Map;
import java.util.List;
import java.util.HashMap;
import org.openflow.protocol.OFFlowMod;
import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFMessage;
import org.openflow.protocol.OFPacketIn;
import org.openflow.protocol.OFPacketOut;
import org.openflow.protocol.OFPort;
import org.openflow.protocol.OFType;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionOutput;
import net.floodlightcontroller.core.util.AppCookie;

import net.floodlightcontroller.topology.NodePortTuple;

import net.floodlightcontroller.routing.IRoutingService;
import net.floodlightcontroller.routing.Route;

import net.floodlightcontroller.devicemanager.SwitchPort;
import org.openflow.protocol.OFMessage;
import org.openflow.protocol.OFType;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPacket;
import net.floodlightcontroller.packet.IPv4;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.util.MACAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.concurrent.ConcurrentSkipListSet;
import java.util.Set;
import net.floodlightcontroller.packet.Ethernet;
import org.openflow.util.HexString;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class AdvNetRouter implements IFloodlightModule, IOFMessageListener {

	protected static final MACAddress MAGIC = MACAddress.valueOf("00:11:00:11:00:11");
        // EDIT HERE

	protected Map<MACAddress, SwitchPort> _mac_to_switchport;

	protected enum RouteMode {
		ROUTE_DIRECT,
		ROUTE_PROXY,
		ROUTE_DROP,
	};

	protected Logger                     _log;
	protected IRoutingService            _routingEngine;

	////////////////////////////////////////////////////////////////////////////
	//
	// IFloodlightModule
	//

	protected IFloodlightProviderService _floodlightProvider;

	@Override //IFloodlightModule
	public void
	init(FloodlightModuleContext context) throws FloodlightModuleException
	{
		_floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
		_routingEngine = context.getServiceImpl(IRoutingService.class);
		_log = LoggerFactory.getLogger("AdvNetRouter");
		
		_mac_to_switchport = new HashMap<MACAddress, SwitchPort>();
		AppCookie.registerApp(100, "AdvNetRouter"); 
	}

	@Override //IFloodlightModule
	public void startUp(FloodlightModuleContext context)
	{
		_floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
	}

	@Override //IFloodlightModule
	public String
	getName()
	{
		return "AdvNetRouter";
	}

	@Override //IFloodlightModule
	public Collection<Class<? extends IFloodlightService>>
	getModuleDependencies()
	{
		Collection<Class<? extends IFloodlightService>> l =
			new ArrayList<Class<? extends IFloodlightService>>();
		l.add(IFloodlightProviderService.class);
		return l;
	}

	@Override //IFloodlightModule
	public boolean
	isCallbackOrderingPrereq(OFType type, String name)
	{
		return false;
	}

	@Override //IFloodlightModule
	public boolean
	isCallbackOrderingPostreq(OFType type, String name)
	{
		return false;
	}

	@Override //IFloodlightModule
	public Collection<Class<? extends IFloodlightService>> 
	getModuleServices()
	{
		return null;
	}

	@Override //IFloodlightModule
	public Map<Class<? extends IFloodlightService>, IFloodlightService>
	getServiceImpls()
	{
		return null;
	}

	////////////////////////////////////////////////////////////////////////////
	//
	// IOFMessageListener
	//

	@Override //IOFMessageListener
	public Command
	receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx)
	{
		OFPacketIn pi;
		Ethernet   pkt;

		if (msg.getType() != OFType.PACKET_IN) {
			return Command.CONTINUE;
		}

		pi  = (OFPacketIn) msg;
		pkt = IFloodlightProviderService.bcStore.get(cntx,
						IFloodlightProviderService.CONTEXT_PI_PAYLOAD);

		IPacket p = pkt.getPayload();
		if ( ! (p instanceof IPv4)) {
			return Command.CONTINUE;
		}

		int        in_port = pi.getInPort();
		int        bufid   = pi.getBufferId();
		MACAddress dl_src  = pkt.getSourceMAC();
		MACAddress dl_dst  = pkt.getDestinationMAC();

		if (dl_dst.equals(MAGIC)) {
			_log.info("MAGIC packet_in: " +
                        	sw.getId() + ":" + in_port + " " +
                        	dl_src + " --> " + dl_dst
                	);

			SwitchPort tmp = new SwitchPort(sw.getId(), in_port);
			_mac_to_switchport.put(dl_src, tmp);
			send_drop_rule(tmp, bufid, dl_src, dl_dst);
			return Command.STOP;
		}

		process_pkt(sw, in_port, bufid, dl_src, dl_dst);
		return Command.STOP;
	}

	private void
	process_pkt(IOFSwitch sw, int in_port, int bufid, MACAddress dl_src, MACAddress dl_dst)
	{
		RouteMode  rm;
		SwitchPort sp_src, sp_dst, sp_prx;

		_log.info("packet_in: " +
			sw.getId() + ":" + in_port + " " +
			dl_src + " --> " + dl_dst
		);

		sp_src = _mac_to_switchport.get(dl_src);
		sp_dst = _mac_to_switchport.get(dl_dst);
		sp_prx = _mac_to_switchport.get(PX);

		if (sp_src == null) {
			_log.error("unknown source port");
			return;
		} else if (sp_dst == null) {
			_log.error("unknown dest port");
			return;
		} else if (sp_prx == null) {
			_log.error("unknown proxy port");
			return;
		}

		rm = getCommMode(dl_src, dl_dst);
		_log.info("packet_in: routing mode: " + rm);

		if (rm == RouteMode.ROUTE_DROP) {

			send_drop_rule(sp_src, bufid, dl_src, dl_dst);

		} else if (rm == RouteMode.ROUTE_PROXY) {

			create_route(sp_src, sp_prx, dl_src, dl_dst, OFPacketOut.BUFFER_ID_NONE);
			create_route(sp_prx, sp_dst, dl_src, dl_dst, OFPacketOut.BUFFER_ID_NONE);
			create_route(sp_dst, sp_prx, dl_dst, dl_src, OFPacketOut.BUFFER_ID_NONE);
			create_route(sp_prx, sp_src, dl_dst, dl_src, bufid);

		} else { // ROUTE_DIRECT

			create_route(sp_src, sp_dst, dl_src, dl_dst, OFPacketOut.BUFFER_ID_NONE);
			create_route(sp_dst, sp_src, dl_dst, dl_src, bufid);
		}
	}

	private RouteMode
	getCommMode(MACAddress src, MACAddress dst)
	{
           // EDIT HERE
	}

	private void
	create_route(
		SwitchPort sp_src, SwitchPort sp_dst,
		MACAddress dl_src, MACAddress dl_dst,
		int bufid)
	{
		Route route =
			_routingEngine.getRoute(
				sp_src.getSwitchDPID(), (short) sp_src.getPort(),
				sp_dst.getSwitchDPID(), (short) sp_dst.getPort(),
				0
			);

		_log.info("Route: " + route);
		List<NodePortTuple> switchPortList = route.getPath();

		for (int indx = switchPortList.size()-1; indx > 0; indx -= 2) {
			// indx and indx-1 will always have the same switch DPID.

			long  dpid     = switchPortList.get(indx).getNodeId();
			short out_port = switchPortList.get(indx).getPortId();
			short in_port  = switchPortList.get(indx-1).getPortId();

			write_flow(dpid, in_port, dl_src, dl_dst, out_port,
  		  	  (indx==1)?bufid:OFPacketOut.BUFFER_ID_NONE);
		}
	}

	private void
	send_drop_rule(SwitchPort sw1, int bufid, MACAddress src, MACAddress dst)
	{
		write_flow(sw1.getSwitchDPID(), (short)sw1.getPort(), src, dst, (short)-1, bufid);
	}

	private void
	write_flow(long dpid, short in_port, MACAddress dl_src, MACAddress dl_dst, short out_port, int bufid)
	{
		List<OFAction> actions = build_output_actions(out_port);
		OFMatch        match   = build_match(in_port, dl_src, dl_dst);
		OFFlowMod      fmod    = build_flowmod(match, actions, bufid);
		IOFSwitch      sw      = _floodlightProvider.getSwitch(dpid);

		_log.info("writing flow mod: " + fmod);

		try {
			sw.write(fmod, null);
		} catch (IOException e) {
			_log.error("error writing flow mod: " + e);
		}
	}

	private List<OFAction>
	build_output_actions(short out_port)
	{
		List<OFAction> actions = new ArrayList<OFAction>();

		if (out_port > 0) {

			OFActionOutput a = new OFActionOutput(out_port);
			actions.add(a);
		}

		return actions;
	}

	private OFMatch
	build_match(short in_port, MACAddress dl_src, MACAddress dl_dst)
	{
		OFMatch match = new OFMatch();
		int wc        = OFMatch.OFPFW_ALL;

		// This /should/ be setting the wildcards and such for us
		//match.fromString("input_port=" + in_port + "," +
		//                 "ip_src=" + IPv4.fromIPv4Address(ip_src) + "," +
		//                 "ip_dst=" + IPv4.fromIPv4Address(ip_dst)
		//);
		
		match.setInputPort(in_port);
		match.setDataLayerSource(dl_src.toBytes());
		match.setDataLayerDestination(dl_dst.toBytes());

		wc &= ~OFMatch.OFPFW_IN_PORT;
		wc &= ~OFMatch.OFPFW_DL_SRC;
		wc &= ~OFMatch.OFPFW_DL_DST;
		match.setWildcards(wc);

		return match;
	}

	private OFFlowMod
	build_flowmod(OFMatch match, List<OFAction> actions, int bufid)
	{
		OFFlowMod fm =
			(OFFlowMod) _floodlightProvider.getOFMessageFactory().getMessage(OFType.FLOW_MOD);
		
		fm.setMatch(match);
		fm.setActions(actions);
		fm.setBufferId(bufid);

		int len = OFFlowMod.MINIMUM_LENGTH + OFActionOutput.MINIMUM_LENGTH * actions.size();
		
		//fm.setIdleTimeout((short)0);
		//fm.setHardTimeout((short)0);
		fm.setCookie(AppCookie.makeCookie(100, 0));
		fm.setCommand(OFFlowMod.OFPFC_ADD);
		fm.setLengthU(len);

		return fm;
	}
}

/* vim: set noet ts=4 sw=4 */
